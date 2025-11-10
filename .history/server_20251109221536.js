// ============== SERVIDOR BACKEND VINTEX CLINIC (v3.1 + FASE C) =============
//
// ARQUITECTURA:
// - FASE A: Modular (Compatible con frontend modular)
// - FASE B: Endpoint /api/citas unificado (maneja 'all' y 'range')
// - FASE C: Storage (4 endpoints) y Real-time (hooks)
// - ESQUEMA: Validado para IDs BIGINT/SERIAL (z.number())
// - FIX 2: Usa la Clave de Servicio (SERVICE_KEY) para bypassear RLS
// - FIX 3: Corregido el nombre de columna 'fecha_cita' a 'fecha_hora'
// - FIX 4: Añadidos logs de diagnóstico para variables de entorno
// - FIX 5 (ACTUAL): Relajada validación de Storage y añadido log de Zod
//
// =======================================================================================

// 1. IMPORTACIÓN DE MÓDULOS
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// 2. CONFIGURACIÓN INICIAL Y DIAGNÓSTICO
const app = express();
app.set('trust proxy', 1); 
const port = process.env.PORT || 80; 

console.log("--- INICIANDO SERVIDOR VINTEX (v3.1 + Fase C) ---");

// Validación de variables de entorno críticas
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const jwtSecret = process.env.JWT_SECRET;

if (!supabaseUrl) console.error("ALERTA: SUPABASE_URL no está definida.");
if (!supabaseServiceKey) console.error("ALERTA: SUPABASE_SERVICE_KEY no está definida.");
if (!jwtSecret) console.error("ALERTA: JWT_SECRET no está definido.");

// 3. MIDDLEWARES GLOBALES
app.use(cors());
app.use(express.json());

// 4. CLIENTE DE SUPABASE (Usando Service Role Key)
const supabase = createClient(supabaseUrl, supabaseServiceKey);
console.log("Cliente de Supabase (Service Role) inicializado.");

// 5. CONFIGURACIÓN DE SEGURIDAD
// 5.1. Rate Limiter (General)
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutos
	max: 1000, // Límite de 1000 peticiones por IP cada 15 min
	message: { error: 'Demasiadas peticiones desde esta IP. Intente más tarde.' },
    standardHeaders: true,
    legacyHeaders: false, 
});

// 5.2. Rate Limiter (Login)
const loginLimiter = rateLimit({
	windowMs: 10 * 60 * 1000, // 10 minutos
	max: 10, // Límite de 10 intentos de login por IP cada 10 min
	message: { error: 'Demasiados intentos de login. Intente más tarde.' },
    standardHeaders: true,
    legacyHeaders: false, 
});

// 5.3. Middleware de Autenticación (JWT)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer <token>"

    if (token == null) {
        return res.status(401).json({ error: 'Token no proporcionado.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            // Si el token está expirado o es inválido
            console.warn("Intento de acceso con token inválido/expirado.");
            return res.status(403).json({ error: 'Token inválido o expirado.' });
        }
        req.user = user; // Almacenamos los datos del usuario (ej. { id: 1, email: 'admin@vintex.com' })
        next();
    });
}

// =======================================================================================
// 6. ESQUEMAS DE VALIDACIÓN (ZOD)
// =======================================================================================

// 6.1. Esquemas de Citas
const idParamSchema = z.object({
    id: z.string().regex(/^\d+$/).transform(Number) // Valida que el ID en la URL sea un número
});

const citaSchema = z.object({
    cliente_id: z.number().int().positive().optional(),
    doctor_id: z.number().int().positive(),
    fecha_hora: z.string().datetime(), // ISO 8601 (ej: "2025-11-05T14:30:00Z")
    duracion_minutos: z.number().int().min(15).max(120),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada']),
    descripcion: z.string().max(500).optional().nullable(),
    
    // Campos para "Nuevo Cliente"
    nombre_cliente: z.string().min(3).optional(),
    telefono_cliente: z.string().min(8).optional(),
});

const citaUpdateSchema = citaSchema.partial(); // Todos los campos son opcionales en PATCH

const citaRangeQuerySchema = z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
});

// 6.2. Esquemas de Clientes
const clienteUpdateSchema = z.object({
    activo: z.boolean().optional(),
    solicitud_de_secretaría: z.boolean().optional()
}).partial();

// 6.3. Esquemas de Doctores
const doctorSchema = z.object({
    nombre: z.string().min(3).max(100),
    especialidad: z.string().max(100),
    color: z.string().regex(/^#[0-9A-Fa-f]{6}$/), // Valida color hex (ej. #FFFFFF)
    horario_inicio: z.string().regex(/^\d{2}:\d{2}$/), // Formato HH:MM
    horario_fin: z.string().regex(/^\d{2}:\d{2}$/),
    activo: z.boolean().default(true)
});

const doctorUpdateSchema = doctorSchema.partial();

// 6.4. Esquemas de Storage (FASE C)
const generateUploadSchema = z.object({
    clienteId: z.number().int().positive(),
    fileName: z.string().min(1).max(255),
    
    // --- INICIO DE CORRECCIÓN ---
    // Se quitó .min(1) para permitir que el navegador envíe
    // un fileType vacío ("") si no reconoce la extensión.
    fileType: z.string().max(100), 
    
    // Se cambió .positive() (mayor a 0) por .min(0) (mayor o igual a 0)
    // para permitir la subida de archivos vacíos (0 bytes).
    fileSize: z.number().int().min(0), // en bytes
    // --- FIN DE CORRECCIÓN ---
});


const confirmUploadSchema = z.object({
    clienteId: z.number().int().positive(),
    storagePath: z.string().min(1),
    fileName: z.string().min(1),
    fileType: z.string().min(1),
    fileSizeKB: z.number().positive(),
});

const getFilesSchema = z.object({
    clienteId: z.string().regex(/^\d+$/).transform(Number)
});

const generateDownloadSchema = z.object({
    storagePath: z.string().min(1)
});


// =======================================================================================
// 7. RUTAS PÚBLICAS (Sin autenticación)
// =======================================================================================

// 7.1. Health Check (Para EasyPanel)
app.get('/', (req, res) => {
    res.status(200).send(`Vintex Clinic API (v3.1 + Fase C) - ${new Date().toISOString()}`);
});

// 7.2. Login (Protegido por Rate Limiter)
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1)
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        // 1. Validar datos de entrada
        const { email, password } = loginSchema.parse(req.body);

        // 2. Buscar al usuario
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('id, email, password_hash')
            .eq('email', email)
            .single();

        if (error || !user) {
            console.warn(`Intento de login fallido (email): ${email}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        // 3. Comparar contraseña
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            console.warn(`Intento de login fallido (pass): ${email}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        // 4. Generar JWT
        const payload = { 
            id: user.id, 
            email: user.email 
            // rol: user.rol (si tuviéramos roles)
        };
        const token = jwt.sign(payload, jwtSecret, { expiresIn: '8h' });

        console.log(`✅ Usuario ${email} autenticado exitosamente.`);
        res.status(200).json({ token: token });

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de login inválidos', details: error.errors });
        console.error("Error en /api/login:", error.message);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
});

// =======================================================================================
// 8. RUTAS PROTEGIDAS (Requieren autenticación)
// =======================================================================================
app.use('/api', apiLimiter, authenticateToken); // Aplicar Auth y Rate Limit a todas las rutas /api/*

// 8.1. Carga Inicial (Doctores, Clientes, Chat)
app.get('/api/initial-data', async (req, res) => {
    console.log(`Petición GET /api/initial-data recibida...`);
    try {
        const [doctores, clientes, chatHistory] = await Promise.all([
            supabase.from('doctores').select('*').order('nombre', { ascending: true }),
            supabase.from('clientes').select('*').order('nombre', { ascending: true }),
            supabase.from('n8n_chat_histories').select('*').order('id', { ascending: false }).limit(1000) // (Ver Riesgo 2 en Informe)
        ]);

        if (doctores.error) throw doctores.error;
        if (clientes.error) throw clientes.error;
        if (chatHistory.error) throw chatHistory.error;

        console.log(`✅ /api/initial-data: ${doctores.data.length} doctores, ${clientes.data.length} clientes, ${chatHistory.data.length} chats.`);
        
        res.status(200).json({
            doctores: doctores.data,
            clientes: clientes.data,
            chatHistory: chatHistory.data
        });
    } catch (error) {
        console.error("Error en /api/initial-data:", error.message);
        res.status(500).json({ error: 'No se pudieron cargar los datos iniciales.', details: error.message });
    }
});


// 8.2. Endpoints de CITAS (Endpoint Unificado - Fase B)

// GET /api/citas (Maneja Rango y Todo)
app.get('/api/citas', async (req, res) => {
    try {
        // Usamos .safeParse() para no lanzar error si los query params no existen
        const queryValidation = citaRangeQuerySchema.safeParse(req.query);

        let query = supabase
            .from('citas')
            .select(`
                *,
                cliente:clientes (nombre, telefono),
                doctor:doctores (nombre, color)
            `);

        // FASE B: Si 'start' y 'end' existen y son válidos, aplicamos filtro de rango
        if (queryValidation.success) {
            const { start, end } = queryValidation.data;
            query = query.gte('fecha_hora', start).lte('fecha_hora', end);
            console.log(`GET /api/citas (Rango: ${start} a ${end})`);
        } else {
            // Si no hay query params, trae todo (para la vista de Pacientes)
            console.log(`GET /api/citas (Todas)`);
        }

        const { data, error } = await query.order('fecha_hora', { ascending: false });
        
        if (error) throw error;
        
        console.log(`✅ /api/citas: ${data.length} citas entregadas.`);
        res.status(200).json(data);

    } catch (error) {
        console.error("Error en GET /api/citas:", error.message);
        res.status(500).json({ error: 'No se pudieron obtener las citas.', details: error.message });
    }
});

// POST /api/citas (Crear)
app.post('/api/citas', async (req, res) => {
    try {
        const { nombre_cliente, telefono_cliente, ...citaData } = citaSchema.parse(req.body);
        let clienteId = citaData.cliente_id;

        // Lógica de "Nuevo Cliente"
        if (!clienteId && nombre_cliente && telefono_cliente) {
            console.log(`Creando nuevo cliente: ${nombre_cliente}`);
            const { data: nuevoCliente, error: clienteError } = await supabase
                .from('clientes')
                .insert({ 
                    nombre: nombre_cliente, 
                    telefono: telefono_cliente,
                    dni: `TEMP-${Date.now()}` // DNI temporal (debe ser UNIQUE)
                })
                .select('id')
                .single();
            
            if (clienteError) throw new Error(`Error al crear cliente: ${clienteError.message}`);
            clienteId = nuevoCliente.id;
        } else if (!clienteId) {
            return res.status(400).json({ error: 'Debe proporcionar un cliente_id o datos de nuevo cliente (nombre, telefono).' });
        }

        // Crear la cita
        const { data, error } = await supabase
            .from('citas')
            .insert({ ...citaData, cliente_id: clienteId })
            .select(`
                *,
                cliente:clientes (nombre, telefono),
                doctor:doctores (nombre, color)
            `)
            .single();

        if (error) throw error;
        
        console.log(`✅ Nueva cita creada (ID: ${data.id}) para cliente ${clienteId}.`);
        res.status(201).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de cita inválidos', details: error.errors });
        console.error("Error en POST /api/citas:", error.message);
        res.status(500).json({ error: 'No se pudo crear la cita.', details: error.message });
    }
});

// PATCH /api/citas/:id (Actualizar)
app.patch('/api/citas/:id', async (req, res) => {
    try {
        const { id: validatedId } = idParamSchema.parse(req.params);
        const dataToUpdate = citaUpdateSchema.parse(req.body);

        if (Object.keys(dataToUpdate).length === 0) {
            return res.status(400).json({ error: 'No se proporcionaron datos para actualizar.' });
        }

        const { data, error } = await supabase
            .from('citas')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select(`
                *,
                cliente:clientes (nombre, telefono),
                doctor:doctores (nombre, color)
            `)
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cita no encontrada.' });
        
        console.log(`✅ Cita ${validatedId} actualizada.`);
        res.status(200).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar cita:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar la cita.', details: error.message });
    }
});

// DELETE /api/citas/:id (Eliminar)
app.delete('/api/citas/:id', async (req, res) => {
    try {
        const { id: validatedId } = idParamSchema.parse(req.params);

        const { data, error } = await supabase
            .from('citas')
            .delete()
            .eq('id', validatedId)
            .select() // Devolver el registro eliminado
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cita no encontrada.' });
        
        console.log(`✅ Cita ${validatedId} eliminada.`);
        res.status(200).json(data); // Devolver el objeto eliminado

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'ID de cita inválido', details: error.errors });
        console.error("Error al eliminar cita:", error.message);
        res.status(500).json({ error: 'No se pudo eliminar la cita.', details: error.message });
    }
});

// 8.3. Endpoints de CLIENTES
app.patch('/api/clientes/:id', async (req, res) => {
    try {
        const { id: validatedId } = idParamSchema.parse(req.params);
        const dataToUpdate = clienteUpdateSchema.parse(req.body);

        if (Object.keys(dataToUpdate).length === 0) {
            return res.status(400).json({ error: 'No se proporcionaron datos para actualizar.' });
        }

        const { data, error } = await supabase
            .from('clientes')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select()
            .single();
        
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cliente no encontrado.' });
        
        console.log(`✅ Cliente ${validatedId} actualizado.`);
        res.status(200).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar cliente:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar el cliente.', details: error.message });
    }
});

// 8.4. Endpoints de DOCTORES
// POST /api/doctores (Crear)
app.post('/api/doctores', async (req, res) => {
    try {
        const doctorData = doctorSchema.parse(req.body);

        const { data, error } = await supabase
            .from('doctores')
            .insert(doctorData)
            .select()
            .single();

        if (error) throw error;
        
        console.log(`✅ Nuevo doctor creado (ID: ${data.id})`);
        res.status(201).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de doctor inválidos', details: error.errors });
        console.error("Error en POST /api/doctores:", error.message);
        res.status(500).json({ error: 'No se pudo crear el doctor.', details: error.message });
    }
});

// PATCH /api/doctores/:id (Actualizar)
app.patch('/api/doctores/:id', async (req, res) => {
    try {
        const { id: validatedId } = idParamSchema.parse(req.params);
        const dataToUpdate = doctorUpdateSchema.parse(req.body);

        if (Object.keys(dataToUpdate).length === 0) {
            return res.status(400).json({ error: 'No se proporcionaron datos para actualizar.' });
        }

        const { data, error } = await supabase
            .from('doctores')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Doctor no encontrado.' });
        
        console.log(`✅ Doctor ${validatedId} actualizado.`);
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar doctor:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar el doctor.', details: error.message });
    }
});

// =======================================================================================
// --- FASE C: ENDPOINTS DE STORAGE (Implementados) ---
// =======================================================================================

const BUCKET_NAME = 'archivos';

// 1. POST /api/files/generate-upload-url
// Genera una URL firmada para que el frontend suba un archivo DIRECTAMENTE a Supabase Storage.
app.post('/api/files/generate-upload-url', async (req, res) => {
    try {
        const { clienteId, fileName, fileType, fileSize } = generateUploadSchema.parse(req.body);
        
        // Creamos una ruta única en el Storage para evitar colisiones
        const storagePath = `public/${clienteId}/${Date.now()}-${fileName}`;

        const { data, error } = await supabase.storage
            .from(BUCKET_NAME)
            .createSignedUploadUrl(storagePath, {
                // Opciones para la subida
                contentType: fileType
            });

        if (error) throw error;

        console.log(`✅ URL de subida generada para: ${storagePath}`);
        res.status(200).json({ 
            signedUrl: data.signedUrl, 
            path: data.path // El frontend necesita guardar este 'path'
        });

    } catch (error) {
        // --- INICIO DE CORRECCIÓN (LOGGING) ---
        if (error instanceof z.ZodError) {
            // Añadimos un log para ver los fallos de validación en el servidor
            console.warn(`Fallo de validación Zod en (generate-upload-url) [400]:`, error.flatten().fieldErrors);
            return res.status(400).json({ error: 'Datos de archivo inválidos', details: error.errors });
        }
        // --- FIN DE CORRECCIÓN (LOGGING) ---
        console.error("Error al generar URL de subida:", error.message);
        res.status(500).json({ error: 'No se pudo generar la URL de subida.', details: error.message });
    }
});

// 2. POST /api/files/confirm-upload
// El frontend llama a este endpoint DESPUÉS de subir el archivo a Supabase
// para registrar la metadata en nuestra tabla 'archivos_adjuntos'.
app.post('/api/files/confirm-upload', async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = confirmUploadSchema.parse(req.body);
        const adminId = req.user.id; // ID del admin que subió el archivo (desde el JWT)

        const metadata = {
            cliente_id: clienteId,
            subido_por_admin_id: adminId,
            storage_path: storagePath,
            file_name: fileName,
            file_type: fileType,
            file_size_kb: fileSizeKB,
        };

        const { data, error } = await supabase
            .from('archivos_adjuntos')
            .insert(metadata)
            .select()
            .single();
        
        if (error) throw error;

        console.log(`✅ Archivo registrado en BD (ID: ${data.id}) para cliente ${clienteId}`);
        res.status(201).json(data); // Devolver el registro de metadata creado

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de confirmación inválidos', details: error.errors });
        console.error("Error al confirmar subida:", error.message);
        res.status(500).json({ error: 'No se pudo registrar el archivo en la BD.', details: error.message });
    }
});

// 3. GET /api/files/:clienteId
// Obtiene la lista de metadata de archivos para un cliente específico.
app.get('/api/files/:clienteId', async (req, res) => {
    try {
        const { clienteId } = getFilesSchema.parse(req.params);

        const { data, error } = await supabase
            .from('archivos_adjuntos')
            .select(`
                *,
                admin:usuarios (email)
            `)
            .eq('cliente_id', clienteId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        console.log(`✅ ${data.length} archivos encontrados para cliente ${clienteId}`);
        res.status(200).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'ID de cliente inválido', details: error.errors });
        console.error("Error al obtener archivos:", error.message);
        res.status(500).json({ error: 'No se pudieron obtener los archivos del cliente.', details: error.message });
    }
});

// 4. POST /api/files/generate-download-url
// Genera una URL firmada y temporal para descargar un archivo.
app.post('/api/files/generate-download-url', async (req, res) => {
    try {
        const { storagePath } = generateDownloadSchema.parse(req.body);

        const { data, error } = await supabase.storage
            .from(BUCKET_NAME)
            .createSignedUrl(storagePath, 60 * 5); // 5 minutos de validez

        if (error) throw error;

        console.log(`✅ URL de descarga generada para: ${storagePath}`);
        res.status(200).json({ signedUrl: data.signedUrl });

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Ruta de archivo inválida', details: error.errors });
        console.error("Error al generar URL de descarga:", error.message);
        res.status(500).json({ error: 'No se pudo generar la URL de descarga.', details: error.message });
    }
});


// =======================================================================================
// 9. INICIO DEL SERVIDOR
// =======================================================================================
app.listen(port, () => {
    console.log(`\n🚀 Servidor Vintex Clinic v3.1 (Fase C) escuchando en el puerto ${port}`);
    console.log("--- Variables de Entorno Cargadas ---");
    console.log(`SUPABASE_URL: ${supabaseUrl ? 'OK' : 'NO ENCONTRADA'}`);
    console.log(`SUPABASE_SERVICE_KEY: ${supabaseServiceKey ? 'OK (***)' : 'NO ENCONTRADA'}`);
    console.log(`JWT_SECRET: ${jwtSecret ? 'OK (***)' : 'NO ENCONTRADA'}`);
    console.log("---------------------------------------\n");
});