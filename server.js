// =============================================
//               SERVER.JS - PARTE 1 DE 3
// =============================================

// IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =============================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tentacionpy_final_db')
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// =============================================
// CONFIGURACIÓN DE CLOUDINARY
// =============================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const getPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;
        const parts = url.split('/');
        const versionIndex = parts.findIndex(part => part.startsWith('v'));
        if (versionIndex === -1) return null;
        const publicIdWithFormat = parts.slice(versionIndex + 1).join('/');
        return publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));
    } catch (e) { console.error("Error extrayendo public_id:", e); return null; }
};

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => ({
        folder: 'tentacionpy_final',
        resource_type: 'auto',
        allowed_formats: ['jpeg', 'png', 'jpg', 'mp4', 'mov', 'avi'],
        transformation: file.mimetype.startsWith('image/') ? [{
            overlay: { font_family: "Poppins", font_size: 50, font_weight: "bold", text: "tentacionpy.com" },
            color: "#FFFFFF", opacity: 40, gravity: "south_east", x: 20, y: 20
        }] : [{
            overlay: { font_family: "Poppins", font_size: 80, text: "tentacionpy.com" },
            color: "white", opacity: 50, gravity: "center"
        }]
    })
});
const upload = multer({ storage });


// =============================================
// CONSTANTES Y MODELOS DE DATOS (ACTUALIZADOS)
// =============================================
const CITIES = ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'];
const CATEGORIES = ['Acompañante', 'Masajes', 'OnlyFans', 'Contenido Digital', 'Shows', 'Otro'];
const CREATOR_EARNING_RATE = 0.55;
const PAGOPAR_PUBLIC_TOKEN = "db3515375d0ac2ba2745b6355458c687";
const PAGOPAR_PRIVATE_TOKEN = "280e500fb8bc93cd782d7fa4435de2f8";

// Schemas
const donationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number }, { timestamps: true });
const commentSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, text: String, donation: donationSchema }, { timestamps: true });
const subscriptionSchema = new mongoose.Schema({ subscriberId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date }, { timestamps: true });

// ===== MODELO DE USUARIO ACTUALIZADO =====
// ===== MODELO DE USUARIO ACTUALIZADO =====
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String }, googleId: { type: String },
    gender: { type: String, enum: ['Mujer', 'Hombre', 'Trans'] }, orientation: { type: String, enum: ['Heterosexual', 'Homosexual', 'Bisexual'] },
    location: { type: String, enum: CITIES }, bio: String, whatsapp: String, profilePic: { type: String, default: '/img/default.png' },
    tpysBalance: { type: Number, default: 100 },
    isVerified: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    purchasedVideos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    likedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
    isAdmin: { type: Boolean, default: false },
    subscriptions: [{ creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date }],
    subscribers: [subscriptionSchema],
    subscriptionSettings: { isActive: { type: Boolean, default: false }, price: { type: Number, enum: [300, 600, 1000, 1250], default: 300 } },
    achievements: { tenSubscribers: { claimed: Boolean }, thousandFollowers: { claimed: Boolean }, tenVideoSales: { claimed: Boolean } },
    automatedChatMessage: { type: String, default: "¡Hola! Gracias por suscribirte. Pide tu video personalizado, ¡precios al privado!" },
    automatedMessageEnabled: { type: Boolean, default: true },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] // <-- AÑADIR ESTA LÍNEA
}, { timestamps: true });

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, type: { type: String, enum: ['image', 'video'] }, files: [String],
    description: String, whatsapp: String, category: { type: String, enum: CATEGORIES }, tags: [String], address: String, services: [String], rate: String,
    price: { type: Number, default: 0 }, salesCount: { type: Number, default: 0 }, isSubscriberOnly: { type: Boolean, default: false },
    views: { type: Number, default: 0 }, likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], comments: [commentSchema],
    boostedUntil: Date,
    boostOptions: { color: String, label: String }
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
    reportingUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reportedPostId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
    type: { type: String, enum: ['user', 'post'], required: true },
    category: { type: String, required: true },
    reason: { type: String, required: true },
    status: { type: String, enum: ['pendiente', 'revisado'], default: 'pendiente' }
}, { timestamps: true });


// ===== MODELO DE TRANSACCIÓN ACTUALIZADO =====
const transactionSchema = new mongoose.Schema({
    type: { type: String, enum: ['video_purchase', 'subscription', 'donation', 'achievement_reward', 'boost', 'tpys_purchase', 'chat_tip', 'admin_adjustment'] }, // <-- NUEVO TIPO
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, 
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // <-- NUEVO CAMPO
    amount: Number, 
    netEarning: Number,
    description: { type: String }, // <-- NUEVO CAMPO para razón de ajuste
    currency: { type: String, enum: ['TPYS', 'PYG'], default: 'TPYS' },
    paymentGatewayId: String,
    status: { type: String, enum: ['PENDIENTE', 'COMPLETADO', 'CANCELADO'], default: 'COMPLETADO' }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number, method: String,
    details: { fullName: String, ci: String, bankName: String, accountNumber: String, phone: String, alias: String },
    status: { type: String, enum: ['Pendiente', 'Procesado', 'Rechazado'], default: 'Pendiente' }
}, { timestamps: true });

const blockedUserSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    blockedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });


const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['like', 'comment', 'follow', 'subscribe', 'sale', 'donation', 'message', 'tip', 'admin'] },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, 
    isRead: { type: Boolean, default: false },
    message: String,
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
    conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    tpysAmount: { type: Number, default: 0 },
    isRead: { type: Boolean, default: false }
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const Report = mongoose.model('Report', reportSchema);
const BlockedUser = mongoose.model('BlockedUser', blockedUserSchema);


// =============================================
// MIDDLEWARES Y PASSPORT (ACTUALIZADO)
// =============================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'super-secret-key-12345', resave: false, saveUninitialized: true, cookie: { secure: 'auto' } }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// Helper para formatear fechas
const formatDate = (date) => {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const diffSeconds = Math.round((now - d) / 1000);
    if (diffSeconds < 60) return 'Justo ahora';
    const diffMinutes = Math.round(diffSeconds / 60);
    if (diffMinutes < 60) return `Hace ${diffMinutes} min`;
    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 24) return `Hace ${diffHours} h`;
    return d.toLocaleDateString('es-PY');
};

// Middleware global para variables locales
app.use(async (req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.CITIES = CITIES;
    res.locals.CATEGORIES = CATEGORIES;
    res.locals.formatDate = formatDate;
    res.locals.path = req.path;
    res.locals.query = req.query; // Para mantener los valores en los formularios de búsqueda
    if (req.user) {
        res.locals.unreadNotifications = await Notification.countDocuments({ userId: req.user._id, isRead: false });
    } else {
        res.locals.unreadNotifications = 0;
    }
    next();
});

// ===== LÓGICA DE LOGIN ACTUALIZADA PARA VERIFICAR BANEO =====
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !user.password) return done(null, false, { message: 'Credenciales incorrectas.' });

        // VERIFICACIÓN DE BANEO
        if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Credenciales incorrectas.' });
        return done(null, user);
    } catch (err) { return done(err); }
}));

const CALLBACK_URL = `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`;
passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            // VERIFICACIÓN DE BANEO EN LOGIN CON GOOGLE
            if (user.isBanned) return done(null, false, { message: 'Esta cuenta ha sido suspendida.' });
            if (!user.googleId) { user.googleId = profile.id; }
            await user.save();
            return done(null, user);
        }
        const newUser = new User({
            googleId: profile.id,
            username: profile.displayName.replace(/\s/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
            isVerified: false,
            gender: 'Mujer',
            orientation: 'Heterosexual'
        });
        await newUser.save();
        return done(null, newUser);
    } catch (err) { return done(err, null); }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { 
        const user = await User.findById(id); 
        done(null, user); 
    } catch (err) { 
        done(err); 
    }
});

// ===== MIDDLEWARE DE AUTENTICACIÓN ACTUALIZADO =====
const requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        // Si el usuario está autenticado, verifica si está baneado en cada request
        if (req.user.isBanned) {
            req.logout((err) => { // Desloguea al usuario baneado
                if(err) return next(err);
                // Aquí podrías añadir un mensaje flash si usas connect-flash
                res.status(403).render('error', { message: 'Tu cuenta ha sido suspendida. Contacta con el soporte.' });
            });
        } else {
            return next(); // Si no está baneado, continúa
        }
    } else {
        res.redirect('/login');
    }
};

const requireAdmin = (req, res, next) => (req.isAuthenticated() && req.user.isAdmin) ? next() : res.status(403).render('error', { message: "Acceso denegado. No tienes permisos de administrador." });

const isPostOwner = async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).render('error', { message: "Publicación no encontrada." });
        // El admin siempre tiene permisos
        if (!post.userId.equals(req.user._id) && !req.user.isAdmin) {
            return res.status(403).render('error', { message: "No tienes permiso para editar esta publicación." });
        }
        res.locals.post = post;
        next();
    } catch (err) { 
        console.error(err);
        res.status(500).render('error', { message: "Error al verificar permisos."});
    }
};

// =============================================
//               FIN DE LA PARTE 1
// =============================================


// =============================================
//               SERVER.JS - PARTE 2 DE 3 (VERSIÓN COMPLETA)
// =============================================

// RUTAS PRINCIPALES Y DE PERFIL
// =============================================
app.get('/', (req, res) => res.redirect('/feed'));

// RUTA /feed FINAL Y CORREGIDA
app.get('/feed', async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 12;

        let filter = {};
        const { search_type, q, username, category, gender, location, show_paid } = req.query;
        
        let resultType = search_type || 'posts';
        
        const activeUserCondition = { isBanned: { $ne: true } };

        if (resultType === 'users') {
            let userFilter = { ...activeUserCondition };
            if (username) userFilter.username = { $regex: username, $options: 'i' };
            if (location) userFilter.location = location;
            if (gender) userFilter.gender = gender;

            const totalUsers = await User.countDocuments(userFilter);
            const totalPages = Math.ceil(totalUsers / itemsPerPage);
            const results = await User.find(userFilter)
                .sort({ createdAt: -1 })
                .skip((page - 1) * itemsPerPage)
                .limit(itemsPerPage);
            
            return res.render('index', { results, resultType, currentPage: page, totalPages });

        } else {
            resultType = 'posts';
            
            const activeUsers = await User.find(activeUserCondition).select('_id');
            const activeUserIds = activeUsers.map(u => u._id);
            filter = { userId: { $in: activeUserIds }, type: 'image', price: 0, isSubscriberOnly: false };

            if (category) filter.category = category;
            if (q) {
                const regex = { $regex: q, $options: 'i' };
                filter.$or = [{ description: regex }, { tags: regex }];
            }
            if (location || gender) {
                const userQuery = { ...activeUserCondition };
                if (location) userQuery.location = location;
                if (gender) userQuery.gender = gender;
                const userIds = await User.find(userQuery).select('_id');
                filter.userId = { $in: userIds.map(u => u._id) };
            }
            if (show_paid === 'on') {
                filter.type = 'video';
                filter.price = { $gt: 0 };
                delete filter.isSubscriberOnly;
            }

            const totalPosts = await Post.countDocuments(filter);
            const totalPages = Math.ceil(totalPosts / itemsPerPage);
            const results = await Post.find(filter)
                .populate('userId')
                .sort({ boostedUntil: -1, createdAt: -1 })
                .skip((page - 1) * itemsPerPage)
                .limit(itemsPerPage);
            
            return res.render('index', { results, resultType, currentPage: page, totalPages });
        }
    } catch (err) { 
        console.error("Error en /feed:", err);
        next(err); 
    }
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res, next) => {
    try {
        const { username, email, password, gender, orientation, location, ageCheck } = req.body;
        if (!ageCheck) throw new Error("Debes confirmar que eres mayor de edad.");
        if (!password) throw new Error("La contraseña es requerida.");
        const existingUser = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
        if (existingUser) throw new Error('El email o nombre de usuario ya está en uso.');
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username, email, password: hashedPassword, gender, orientation, location });
        await user.save();
        req.login(user, (err) => { if (err) return next(err); res.redirect('/feed'); });
    } catch (err) { res.render('register', { error: err.message }); }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', passport.authenticate('local', { successRedirect: '/feed', failureRedirect: '/login' }));

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy(() => res.redirect('/'));
    });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/feed'));

app.get('/profile', requireAuth, (req, res) => res.redirect(`/user/${req.user.username}`));

app.get('/user/:username', async (req, res, next) => {
    try {
        const userProfile = await User.findOne({ username: req.params.username.toLowerCase() });

        if (!userProfile || userProfile.isBanned) {
            return res.status(404).render('error', { message: 'Usuario no encontrado o suspendido.' });
        }

        // --- INICIO DE COMPROBACIÓN DE BLOQUEO ---
        if (req.user) {
            const currentUser = await User.findById(req.user._id);
            const isBlockedByProfile = userProfile.blockedUsers.includes(currentUser._id);
            const isBlockingProfile = currentUser.blockedUsers.includes(userProfile._id);

            if(isBlockedByProfile || isBlockingProfile) {
                 return res.render('profile-blocked', { username: userProfile.username });
            }
        }
         // --- FIN DE COMPROBACIÓN DE BLOQUEO ---


        const posts = await Post.find({ userId: userProfile._id }).sort({ createdAt: -1 });
        let isSubscribed = false;
        if (req.user) {
            isSubscribed = !!req.user.subscriptions.find(s => s.creatorId.equals(userProfile._id) && new Date(s.endDate) > new Date());
        }

        const viewToRender = req.user && req.user._id.equals(userProfile._id) ? 'profile' : 'user-profile';
        res.render(viewToRender, { userProfile, posts, isSubscribed });
    } catch (err) {
        next(err);
    }
});

app.post('/user/:id/follow', requireAuth, async (req, res, next) => {
    try {
        const userToFollow = await User.findById(req.params.id);
        if (!userToFollow || req.user._id.equals(userToFollow._id)) return res.redirect('back');
        const currentUser = await User.findById(req.user._id);
        const isFollowing = currentUser.following.some(id => id.equals(userToFollow._id));
        if (isFollowing) {
            await User.findByIdAndUpdate(currentUser._id, { $pull: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $pull: { followers: currentUser._id } });
        } else {
            await User.findByIdAndUpdate(currentUser._id, { $addToSet: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $addToSet: { followers: currentUser._id } });
            await new Notification({ userId: userToFollow._id, actorId: currentUser._id, type: 'follow', message: 'ha comenzado a seguirte.' }).save();
        }
        res.redirect('back');
    } catch (err) { next(err); }
});

// =============================================
// RUTAS DE POSTS Y CONTENIDO
// =============================================
app.get('/new-post', requireAuth, (req, res) => res.render('new-post'));
app.post('/new-post', requireAuth, upload.array('files', 10), async (req, res, next) => {
    try {
        const { type, description, price, services, rate, address, whatsapp, category, tags, isSubscriberOnly } = req.body;
        if (!req.files || req.files.length === 0) throw new Error("Debes subir al menos un archivo.");
        const newPost = new Post({
            userId: req.user._id, type, files: req.files.map(f => f.path), description, whatsapp: whatsapp || req.user.whatsapp, category,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            price: type === 'video' && !(isSubscriberOnly === 'on') ? parseFloat(price) : 0,
            services: type === 'image' && services ? services.split(',').map(s => s.trim()) : [],
            rate: type === 'image' ? rate : '', address: type === 'image' ? address : '',
            isSubscriberOnly: isSubscriberOnly === 'on'
        });
        await newPost.save();
        res.redirect(`/anuncio/${newPost._id}`);
    } catch (err) { next(err); }
});

app.get('/anuncio/:id', async (req, res, next) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
            .populate({ path: 'userId', match: { isBanned: { $ne: true } } })
            .populate({ path: 'comments', populate: { path: 'userId', select: 'username profilePic' } });
        if (!post || !post.userId) return res.status(404).render('error', { message: 'Este contenido ya no está disponible.' });
        const recommendedPosts = await Post.find({ _id: { $ne: post._id }, category: post.category, userId: post.userId }).limit(4).populate('userId', 'username profilePic');
        let canView = true, isOwner = false, hasPurchased = false, hasSubscriptionAccess = false;
        if (req.user) {
            isOwner = post.userId.equals(req.user._id);
            if (post.type === 'video') {
                hasPurchased = req.user.purchasedVideos.includes(post._id);
                const sub = req.user.subscriptions.find(s => s.creatorId.equals(post.userId._id) && new Date(s.endDate) > new Date());
                hasSubscriptionAccess = post.isSubscriberOnly && !!sub;
                canView = isOwner || hasPurchased || hasSubscriptionAccess || req.user.isAdmin;
            }
        }
        res.render('anuncio-detail', { post, canView, isOwner, hasPurchased, hasSubscriptionAccess, recommendedPosts });
    } catch (err) { next(err); }
});

app.post('/post/:id/delete', requireAuth, isPostOwner, async (req, res, next) => {
    try {
        const post = res.locals.post;
        for (const fileUrl of post.files) {
            const publicId = getPublicId(fileUrl);
            if (publicId) await cloudinary.uploader.destroy(publicId, { resource_type: fileUrl.includes('/video/') ? 'video' : 'image' }).catch(err => console.log("Cloudinary destroy failed:", err));
        }
        await Post.findByIdAndDelete(req.params.id);
        const redirectUrl = req.originalUrl.includes('/admin') ? '/admin/posts' : '/profile';
        res.json({ success: true, redirectUrl });
    } catch (err) { next(err); }
});

// ===========================================
// RUTA DE LIKE - VERSIÓN FINAL Y CORRECTA
// ===========================================
app.post('/post/:id/like', requireAuth, async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ success: false, message: "Publicación no encontrada." });
        }

        const userId = req.user._id;
        // La lógica original para dar/quitar like estaba bien, la mantenemos
        const likedIndex = post.likes.indexOf(userId);
        let isLikedNow = false;

        if (likedIndex > -1) {
            post.likes.splice(likedIndex, 1); // Quita el like
        } else {
            post.likes.push(userId); // Añade el like
            isLikedNow = true;
        }

        await post.save();

        // Respuesta JSON para el script del frontend
        res.json({
            success: true,
            likes: post.likes.length,
            liked: isLikedNow
        });

    } catch (err) {
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

app.post('/post/:id/comments', requireAuth, async (req, res) => {
    const { text, donationAmount } = req.body;
    const dbSession = await mongoose.startSession();
    try {
        let populatedComment;
        await dbSession.withTransaction(async (session) => {
            const post = await Post.findById(req.params.id).session(session);
            if (!post) throw new Error("Post no encontrado");
            const commenter = await User.findById(req.user._id).session(session);
            const amount = Number(donationAmount) || 0;
            if (amount > 0 && commenter.tpysBalance < amount) throw new Error("No tienes suficientes TPYS para donar.");
            const newCommentData = { userId: commenter._id, text };
            if (amount > 0) {
                const isSelfDonation = commenter._id.equals(post.userId);
                const netEarning = amount * CREATOR_EARNING_RATE;
                if (isSelfDonation) {
                    commenter.tpysBalance = commenter.tpysBalance - amount + netEarning;
                    await commenter.save({ session });
                    await new Transaction({ type: 'donation', sellerId: commenter._id, buyerId: commenter._id, postId: post._id, amount, netEarning }).save({ session });
                } else {
                    const creator = await User.findById(post.userId).session(session);
                    if (!creator) throw new Error("Creador no encontrado.");
                    commenter.tpysBalance -= amount;
                    creator.tpysBalance += netEarning;
                    await commenter.save({ session });
                    await creator.save({ session });
                    await new Transaction({ type: 'donation', sellerId: creator._id, buyerId: commenter._id, postId: post._id, amount, netEarning }).save({ session });
                    await new Notification({ userId: creator._id, actorId: commenter._id, type: 'donation', postId: post._id, message: `te donó ${amount} TPYS en tu post.` }).save({ session });
                }
                newCommentData.donation = { userId: commenter._id, amount };
            }
            post.comments.push(newCommentData);
            await post.save({ session });
            if (!post.userId.equals(commenter._id)) {
                await new Notification({ userId: post.userId, actorId: commenter._id, type: 'comment', postId: post._id, message: `comentó tu post.` }).save({ session });
            }
            await post.populate({ path: 'comments.userId', select: 'username profilePic' });
            populatedComment = post.comments.slice(-1)[0];
        });
        res.status(200).json({ success: true, comment: populatedComment });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message || 'Error interno del servidor.' });
    } finally {
        await dbSession.endSession();
    }
});

// =============================================
// RUTAS DE PÁGINAS ESTÁTICAS Y DE USUARIO
// =============================================
app.get('/my-videos', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({ path: 'purchasedVideos', populate: { path: 'userId', select: 'username profilePic' } });
        res.render('my-videos', { videos: user.purchasedVideos });
    } catch (err) { next(err); }
});

app.get('/my-likes', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({ path: 'likedPosts', populate: { path: 'userId', select: 'username profilePic' } });
        res.render('my-likes', { posts: user.likedPosts });
    } catch (err) { next(err); }
});

app.get('/notifications', requireAuth, async (req, res, next) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id }).populate('actorId', 'username profilePic').populate('postId', 'description type files').sort({ createdAt: -1 });
        await Notification.updateMany({ userId: req.user._id, isRead: false }, { $set: { isRead: true } });
        res.render('notifications', { notifications });
    } catch (err) { next(err); }
});

app.get('/terms', (req, res) => res.render('terms'));
app.get('/payout-info', requireAuth, (req, res) => res.render('payout-info'));



// =============================================
// NUEVAS RUTAS PARA LISTAS, BLOQUEO Y REPORTES
// =============================================

// --- LISTA DE SUSCRIPCIONES ---
app.get('/my-subscriptions', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({
            path: 'subscriptions.creatorId',
            model: 'User'
        });

        const activeSubscriptions = user.subscriptions
            .filter(s => s.creatorId) // <-- LÍNEA AÑADIDA: Filtra suscripciones sin creador (nulas)
            .filter(s => new Date(s.endDate) > new Date());

        res.render('list-subscriptions.html', { subscriptions: activeSubscriptions });
    } catch (err) {
        next(err);
    }
});

// --- LISTA DE SEGUIDORES Y SEGUIDOS ---
app.get('/user/:username/list/:type', requireAuth, async (req, res, next) => {
    try {
        const { username, type } = req.params;
        const profileUser = await User.findOne({ username });
        if (!profileUser) return res.status(404).render('error', { message: 'Usuario no encontrado.' });

        const validTypes = ['followers', 'following'];
        if (!validTypes.includes(type)) return res.redirect(`/user/${username}`);

        const list = await User.find({ _id: { $in: profileUser[type] } });

        res.render('followers', {
            title: type === 'followers' ? 'Seguidores' : 'Siguiendo',
            user: profileUser,
            list: list
        });
    } catch (err) {
        next(err);
    }
});

// --- BLOQUEAR USUARIO ---
app.post('/user/:id/block', requireAuth, async (req, res, next) => {
    try {
        const userToBlockId = req.params.id;
        const currentUser = await User.findById(req.user._id);

        if (currentUser._id.equals(userToBlockId)) {
            return res.status(400).json({ success: false, message: "No puedes bloquearte a ti mismo." });
        }

        const isBlocked = currentUser.blockedUsers.includes(userToBlockId);

        if (isBlocked) {
            // Desbloquear
            await User.findByIdAndUpdate(currentUser._id, { $pull: { blockedUsers: userToBlockId } });
        } else {
            // Bloquear
            await User.findByIdAndUpdate(currentUser._id, {
                $addToSet: { blockedUsers: userToBlockId },
                $pull: { following: userToBlockId, followers: userToBlockId } // Dejar de seguir mutuamente
            });
            await User.findByIdAndUpdate(userToBlockId, {
                $pull: { following: currentUser._id, followers: currentUser._id }
            });
        }
        res.json({ success: true, redirectUrl: '/feed' });
    } catch (err) {
        next(err);
    }
});


// --- VISTA DE USUARIOS BLOQUEADOS (CORREGIDO) ---
app.get('/settings/blocked', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate('blockedUsers');
        // Se corrige la ruta para que coincida con tu archivo: views/settings/blocked-user.html
        res.render('settings/blocked-user', { blockedUsers: user.blockedUsers });
    } catch (err) {
        next(err);
    }
});


// --- FORMULARIO DE REPORTE ---
app.get('/report', requireAuth, (req, res) => {
    const { type, id } = req.query;
    res.render('report-form', {
        type, id,
        REPORT_CATEGORIES: ['Contenido inapropiado', 'Spam', 'Acoso', 'Estafa o Fraude', 'Otro']
    });
});

// --- PROCESAR REPORTE ---
app.post('/report', requireAuth, async (req, res, next) => {
    try {
        const { type, id, category, reason } = req.body;
        const report = new Report({
            reportingUserId: req.user._id,
            type,
            category,
            reason
        });

        if (type === 'user') {
            report.reportedUserId = id;
        } else {
            report.reportedPostId = id;
        }

        await report.save();
        res.render('report-success');
    } catch (err) {
        next(err);
    }
});


// --- VISTA DE ADMIN PARA REPORTES ---
app.get('/admin/reports', requireAdmin, async (req, res, next) => {
    try {
        const reports = await Report.find({ status: 'pendiente' })
            .populate('reportingUserId', 'username')
            .populate('reportedUserId', 'username')
            .populate('reportedPostId', '_id')
            .sort({ createdAt: -1 });

        res.render('admin/reports', { reports, layout: 'admin/layout' });
    } catch (err) {
        next(err);
    }
});

// --- ACTUALIZAR ESTADO DE REPORTE ---
app.post('/admin/report/:id/update', requireAdmin, async (req, res, next) => {
    try {
        await Report.findByIdAndUpdate(req.params.id, { status: 'revisado' });
        res.redirect('/admin/reports');
    } catch (err) {
        next(err);
    }
});

// =============================================
// RUTAS DE MONETIZACIÓN (COMPLETAS)
// =============================================
app.post('/post/:id/boost', requireAuth, isPostOwner, async (req, res, next) => {
    const { boost, boostLabel, boostColor } = req.body;
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const post = await Post.findById(req.params.id).session(session);
            const user = await User.findById(req.user._id).session(session);
            const [plan, cost] = boost.split('_');
            const boostCost = parseInt(cost, 10);
            const boostDays = { viral: 1, tendencia: 3, hot: 10 }[plan];
            if (user.tpysBalance < boostCost) throw new Error('No tienes suficientes TPYS.');
            user.tpysBalance -= boostCost;
            post.boostedUntil = new Date(Date.now() + boostDays * 24 * 60 * 60 * 1000);
            post.boostOptions = { color: boostColor, label: boostLabel };
            await new Transaction({ type: 'boost', buyerId: user._id, postId: post._id, amount: boostCost, netEarning: 0 }).save({ session });
            await user.save({ session });
            await post.save({ session });
        });
        res.json({ success: true, message: "¡Anuncio promocionado!", redirectUrl: `/anuncio/${req.params.id}` });
    } catch (err) { res.status(400).json({ success: false, message: err.message }); } finally { await dbSession.endSession(); }
});

app.post('/buy-video/:id', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const post = await Post.findById(req.params.id).session(session);
            if (!post || post.type !== 'video' || post.isSubscriberOnly) throw new Error('Video no disponible.');
            const buyer = await User.findById(req.user._id).session(session);
            if (buyer.tpysBalance < post.price) throw new Error('No tienes suficientes TPYS.');
            if (buyer.purchasedVideos.includes(post._id)) throw new Error('Ya has comprado este video.');
            const seller = await User.findById(post.userId).session(session);
            const price = post.price;
            const netEarning = price * CREATOR_EARNING_RATE;
            buyer.tpysBalance -= price;
            seller.tpysBalance += netEarning;
            buyer.purchasedVideos.push(post._id);
            post.salesCount += 1;
            await buyer.save({ session });
            await seller.save({ session });
            await post.save({ session });
            await new Transaction({ type: 'video_purchase', sellerId: seller._id, buyerId: buyer._id, postId: post._id, amount: price, netEarning }).save({ session });
            await new Notification({ userId: seller._id, actorId: buyer._id, type: 'sale', postId: post._id, message: `ha comprado tu video.` }).save({ session });
        });
        res.json({ success: true, message: "¡Compra exitosa!" });
    } catch (err) { res.status(400).json({ success: false, message: err.message }); } finally { await dbSession.endSession(); }
});

app.post('/user/:id/subscribe', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const creator = await User.findById(req.params.id).session(session);
            if (!creator || !creator.subscriptionSettings.isActive) throw new Error("Las suscripciones para este creador no están activas.");

            const buyer = await User.findById(req.user._id).session(session);
            const price = creator.subscriptionSettings.price;

            if (buyer._id.equals(creator._id)) throw new Error("No puedes suscribirte a ti mismo.");
            if (buyer.tpysBalance < price) throw new Error("No tienes suficientes TPYS para suscribirte.");

            const netEarning = price * CREATOR_EARNING_RATE;
            buyer.tpysBalance -= price;
            creator.tpysBalance += netEarning;

            const now = new Date();
            const existingSubIndex = buyer.subscriptions.findIndex(s => s.creatorId.equals(creator._id));
            let newEndDate = new Date(new Date(now).setMonth(now.getMonth() + 1));

            if (existingSubIndex > -1) {
                const currentEndDate = new Date(buyer.subscriptions[existingSubIndex].endDate);
                if (currentEndDate > now) {
                    newEndDate = new Date(currentEndDate.setMonth(currentEndDate.getMonth() + 1));
                }
                buyer.subscriptions[existingSubIndex].endDate = newEndDate;
            } else {
                buyer.subscriptions.push({ creatorId: creator._id, endDate: newEndDate });
            }

            const subscriberIndex = creator.subscribers.findIndex(s => s.subscriberId.equals(buyer._id));
            if (subscriberIndex > -1) {
                creator.subscribers[subscriberIndex].endDate = newEndDate;
            } else {
                creator.subscribers.push({ subscriberId: buyer._id, endDate: newEndDate });
            }
            
            // Lógica de conversación y mensaje automático
            let conversation = await Conversation.findOne({ participants: { $all: [buyer._id, creator._id] } }).session(session);
            if (!conversation) {
                conversation = new Conversation({ participants: [buyer._id, creator._id] });
                await conversation.save({ session });
            }

            if (creator.automatedMessageEnabled && creator.automatedChatMessage) {
                const autoMessage = new Message({
                    conversationId: conversation._id,
                    senderId: creator._id,
                    text: creator.automatedChatMessage
                });
                await autoMessage.save({ session });
                conversation.lastMessage = autoMessage._id;
                await conversation.save({ session });
                await new Notification({
                    userId: buyer._id,
                    actorId: creator._id,
                    type: 'message',
                    message: `Te ha enviado un mensaje.`
                }).save({ session });
            }


            await new Transaction({ type: 'subscription', sellerId: creator._id, buyerId: buyer._id, amount: price, netEarning }).save({ session });
            await new Notification({ userId: creator._id, actorId: buyer._id, type: 'subscribe', message: `se ha suscrito a tu perfil.` }).save({ session });

            await buyer.save({ session });
            await creator.save({ session });
        });

        res.json({ success: true, message: '¡Suscripción exitosa!' });
    } catch (err) {
        res.status(400).json({ success: false, message: err.message });
    } finally {
        await dbSession.endSession();
    }
});

app.get('/add-funds', requireAuth, (req, res) => res.render('add-funds'));
app.post('/pagopar/create-order', requireAuth, async (req, res) => {
    try {
        const { amountGs, tpysAmount } = req.body;
        const amount = parseInt(amountGs, 10);
        const orderId = `TPY-${req.user._id.toString().slice(-4)}-${Date.now()}`;
        const hash = crypto.createHash('md5').update(PAGOPAR_PRIVATE_TOKEN + orderId + amount).digest('hex');
        const orderData = {
            "token": hash, "comprador": { "ruc": "0", "email": req.user.email, "nombre": req.user.username, "telefono": "0999999999", "direccion": "N/A", "documento": "0", "razon_social": req.user.username, "tipo_documento": "CI" },
            "public_key": PAGOPAR_PUBLIC_TOKEN, "monto_total": amount, "tipo_pedido": "VENTA-COMERCIO",
            "id_pedido_comercio": orderId, "descripcion_resumen": `Compra de ${tpysAmount} TPYS`,
            "fecha_maxima_pago": new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10).replace(/-/g, ""),
            "url_retorno_ok": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-success`,
            "url_retorno_error": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-error`,
            "url_notificacion_pedido": `${process.env.BASE_URL || 'http://localhost:3000'}/pagopar/callback`
        };
        const response = await fetch('https://api.pagopar.com/api/pedido/generar/desarrollo', { method: 'POST', body: JSON.stringify(orderData), headers: { 'Content-Type': 'application/json' } });
        const jsonResponse = await response.json();
        if (jsonResponse.respuesta === true) {
            await new Transaction({ type: 'tpys_purchase', buyerId: req.user._id, amount, netEarning: parseInt(tpysAmount, 10), currency: 'PYG', paymentGatewayId: orderId, status: 'PENDIENTE' }).save();
            res.json({ success: true, paymentUrl: jsonResponse.resultado[0].data });
        } else { throw new Error(jsonResponse.resultado || 'Error con Pagopar'); }
    } catch (err) { res.status(500).json({ success: false, message: 'Error al crear la orden de pago.' }); }
});

app.post('/pagopar/callback', async (req, res) => {
    const { hash, id_pedido_comercio, estado } = req.body;
    const localHash = crypto.createHash('sha1').update(PAGOPAR_PRIVATE_TOKEN + id_pedido_comercio + estado).digest('hex');
    if (hash !== localHash) return res.status(403).send("Hash inválido.");
    const dbSession = await mongoose.startSession();
    try {
        await dbSession.withTransaction(async (session) => {
            const transaction = await Transaction.findOne({ paymentGatewayId: id_pedido_comercio, status: 'PENDIENTE' }).session(session);
            if (transaction) {
                if (estado === 'pagado') {
                    const user = await User.findById(transaction.buyerId).session(session);
                    user.tpysBalance += transaction.netEarning;
                    transaction.status = 'COMPLETADO';
                    await user.save({ session });
                    await transaction.save({ session });
                } else if (estado === 'cancelado') {
                    transaction.status = 'CANCELADO';
                    await transaction.save({ session });
                }
            }
        });
        res.status(200).send("OK");
    } catch (err) { res.status(500).send("Error al procesar el pago."); } finally { await dbSession.endSession(); }
});

app.get('/payment-success', (req, res) => res.render('payment-status', { success: true, message: '¡Pago exitoso! Tu saldo ha sido actualizado.' }));
app.get('/payment-error', (req, res) => res.render('payment-status', { success: false, message: 'El pago ha fallado o ha sido cancelado.' }));

// =============================================
// RUTAS DE CHAT (COMPLETAS)
// =============================================
app.get('/chat', requireAuth, async (req, res, next) => {
    try {
        const conversations = await Conversation.find({ participants: req.user._id }).populate('participants', 'username profilePic').populate({ path: 'lastMessage', select: 'text createdAt' }).sort({ 'lastMessage.createdAt': -1 });
        res.render('chat-list', { conversations });
    } catch (err) { next(err); }
});

app.get('/chat/with/:userId', requireAuth, async (req, res, next) => {
    const { userId } = req.params;
    if (req.user._id.equals(userId)) return res.redirect('/chat');
    try {
        let conversation = await Conversation.findOne({ participants: { $all: [req.user._id, userId] } });
        if (!conversation) {
            const creator = await User.findById(userId);
            const isSubscribed = req.user.subscriptions.some(s => s.creatorId.equals(creator._id) && new Date(s.endDate) > new Date());
            if (!isSubscribed && !creator.followers.includes(req.user._id)) { // Permite iniciar chat si lo sigues
                return res.status(403).render('error', { message: 'Debes suscribirte o seguir a este usuario para chatear.' });
            }
            conversation = new Conversation({ participants: [req.user._id, userId] });
            await conversation.save();
        }
        res.redirect(`/chat/${conversation._id}`);
    } catch (err) { next(err); }
});

app.get('/chat/:conversationId', requireAuth, async (req, res, next) => {
    try {
        const conversation = await Conversation.findById(req.params.conversationId).populate('participants', 'username profilePic');
        if (!conversation || !conversation.participants.some(p => p._id.equals(req.user._id))) return res.status(403).render('error', { message: 'No tienes acceso a este chat.' });
        const messages = await Message.find({ conversationId: conversation._id }).populate('senderId', 'username profilePic').sort('createdAt');
        const otherUser = conversation.participants.find(p => !p._id.equals(req.user._id));
        await Message.updateMany({ conversationId: conversation._id, senderId: otherUser._id, isRead: false }, { $set: { isRead: true } });
        res.render('chat-detail', { conversation, messages, otherUser });
    } catch (err) { next(err); }
});

app.post('/chat/:conversationId/messages', requireAuth, async (req, res, next) => {
    const { text, tpysAmount } = req.body;
    const amount = Number(tpysAmount) || 0;
    const dbSession = await mongoose.startSession();
    try {
        let populatedMessage;
        await dbSession.withTransaction(async (session) => {
            const conversation = await Conversation.findById(req.params.conversationId).session(session);
            if (!conversation.participants.includes(req.user._id)) throw new Error("No eres parte de esta conversación.");
            const sender = await User.findById(req.user._id).session(session);
            const receiverId = conversation.participants.find(p => !p.equals(sender._id));
            const receiver = await User.findById(receiverId).session(session);
            if (amount > 0) {
                if (sender.tpysBalance < amount) throw new Error("No tienes suficientes TPYS.");
                const netEarning = amount * CREATOR_EARNING_RATE;
                sender.tpysBalance -= amount;
                receiver.tpysBalance += netEarning;
                await new Transaction({ type: 'chat_tip', sellerId: receiver._id, buyerId: sender._id, amount, netEarning }).save({ session });
                await new Notification({ userId: receiver._id, actorId: sender._id, type: 'tip', message: `te envió ${amount} TPYS en el chat.` }).save({ session });
            }
            const newMessage = new Message({ conversationId: conversation._id, senderId: sender._id, text, tpysAmount: amount });
            conversation.lastMessage = newMessage._id;
            await sender.save({ session });
            if (amount > 0) await receiver.save({ session });
            await newMessage.save({ session });
            await conversation.save({ session });
            populatedMessage = await newMessage.populate('senderId', 'username profilePic');
        });
        res.json({ success: true, message: populatedMessage });
    } catch (err) { res.status(400).json({ success: false, message: err.message }); } finally { await dbSession.endSession(); }
});

// =============================================
//               FIN DE LA PARTE 2
// =============================================




// =============================================
//               SERVER.JS - PARTE 3 DE 3 (FINAL)
// =============================================

// RUTAS DEL PANEL DE CONFIGURACIÓN DEL CREADOR
// =============================================
app.get('/settings/:page', requireAuth, async (req, res, next) => {
    try {
        app.set('layout', 'settings/layout'); // Usar el layout del panel de configuración
        const { page } = req.params;
        const validPages = ['dashboard', 'profile', 'subscriptions', 'automations', 'payouts'];
        if (!validPages.includes(page)) return res.redirect('/settings/dashboard');

        let data = { page };

        if (page === 'dashboard') {
            const transactions = await Transaction.find({ sellerId: req.user._id }).populate('buyerId', 'username').sort({ createdAt: -1 });
            const totalNetEarnings = transactions.reduce((sum, t) => sum + (t.netEarning || 0), 0);
            const activeSubscribers = req.user.subscribers.filter(s => new Date(s.endDate) > new Date()).length;
            data = { ...data, totalNetEarnings, transactions, activeSubscribersCount: activeSubscribers };
        }
        if (page === 'payouts') {
            data.withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ createdAt: -1 });
        }
        res.render(`settings/${page}`, data);
    } catch(err) { next(err); }
});

app.post('/settings/profile', requireAuth, upload.single('profilePic'), async (req, res, next) => {
    try {
        const { username, bio, location, whatsapp, gender, orientation } = req.body;
        const userToUpdate = await User.findById(req.user._id);
        
        if (req.file && userToUpdate.profilePic && !userToUpdate.profilePic.includes('default.png')) {
            const publicId = getPublicId(userToUpdate.profilePic);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        const updateData = { username, bio, location, whatsapp, gender, orientation };
        if (req.file) updateData.profilePic = req.file.path;
        await User.findByIdAndUpdate(req.user._id, updateData);
        res.redirect('/settings/profile');
    } catch (err) { next(err); }
});

app.post('/settings/subscriptions', requireAuth, async (req, res) => {
    const { isActive, price } = req.body;
    req.user.subscriptionSettings.isActive = isActive === 'on';
    if (price) req.user.subscriptionSettings.price = Number(price);
    await req.user.save();
    res.redirect('/settings/subscriptions');
});

app.post('/settings/automations', requireAuth, async (req, res) => {
    const { automatedMessageEnabled, automatedChatMessage } = req.body;
    req.user.automatedMessageEnabled = automatedMessageEnabled === 'on';
    req.user.automatedChatMessage = automatedChatMessage;
    await req.user.save();
    res.redirect('/settings/automations');
});

app.post('/settings/payouts', requireAuth, async (req, res, next) => {
    try {
        const { amount, method, fullName, ci, bankName, accountNumber, phone, alias } = req.body;
        const user = req.user;
        const amountNum = parseInt(amount);
        if (isNaN(amountNum) || amountNum < 30000) throw new Error(`El monto mínimo es de 30.000 Gs.`);
        const tpysToWithdraw = Math.floor(amountNum / 100);
        if (user.tpysBalance < tpysToWithdraw) throw new Error("No tienes suficientes TPYS para retirar ese monto.");
        
        let details = {};
        if (method === 'transferencia') details = { fullName, ci, bankName, accountNumber, alias };
        else if (method === 'giro') details = { fullName, ci, phone };
        else throw new Error("Método de retiro no válido.");
        
        await User.findByIdAndUpdate(user._id, { $inc: { tpysBalance: -tpysToWithdraw } });
        await new Withdrawal({ userId: user._id, amount: amountNum, method, details, status: 'Pendiente' }).save();
        
        res.redirect('/settings/payouts');
    } catch(err) { next(err); }
});


// =============================================
// RUTAS DE ADMINISTRADOR (NUEVAS Y MEJORADAS)
// =============================================
app.get('/admin', requireAdmin, (req, res) => res.redirect('/admin/dashboard'));

app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
    try {
        const [totalUsers, totalPosts, pendingWithdrawals] = await Promise.all([
            User.countDocuments(),
            Post.countDocuments(),
            Withdrawal.countDocuments({ status: 'Pendiente' })
        ]);
        const stats = { totalUsers, totalPosts, pendingWithdrawals };
        res.render('admin/dashboard', { stats, layout: 'admin/layout' });
    } catch (err) { next(err); }
});

// --- GESTIÓN DE USUARIOS ---
app.get('/admin/users', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            const regex = { $regex: req.query.search, $options: 'i' };
            query = { $or: [{ username: regex }, { email: regex }] };
        }
        const totalUsers = await User.countDocuments(query);
        const totalPages = Math.ceil(totalUsers / itemsPerPage);
        const users = await User.find(query).sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/users', { users, totalPages, currentPage: page, layout: 'admin/layout' });
    } catch (err) { next(err); }
});

app.get('/admin/user/:id', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.redirect('/admin/users');
        const transactions = await Transaction.find({ $or: [{ buyerId: user._id }, { sellerId: user._id }] }).populate('buyerId sellerId postId adminId').sort({ createdAt: -1 }).limit(20);
        res.render('admin/user-detail', { user, transactions, layout: 'admin/layout' });
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/toggle-ban', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user && !user.isAdmin) { // Previene que el admin se banee a sí mismo
            user.isBanned = !user.isBanned;
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/toggle-verify', requireAdmin, async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (user) {
            user.isVerified = !user.isVerified;
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

app.post('/admin/user/:id/adjust-balance', requireAdmin, async (req, res, next) => {
    try {
        const { amount, reason } = req.body;
        const amountNum = parseInt(amount);
        if (isNaN(amountNum)) return res.redirect(`/admin/user/${req.params.id}`);
        const user = await User.findById(req.params.id);
        if (user) {
            user.tpysBalance += amountNum;
            await new Transaction({ type: 'admin_adjustment', buyerId: user._id, adminId: req.user._id, amount: amountNum, description: reason }).save();
            await user.save();
        }
        res.redirect(`/admin/user/${req.params.id}`);
    } catch (err) { next(err); }
});

// --- GESTIÓN DE CONTENIDO ---
app.get('/admin/posts', requireAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 15;
        let query = {};
        if (req.query.search) {
            query.description = { $regex: req.query.search, $options: 'i' };
        }
        const totalPosts = await Post.countDocuments(query);
        const totalPages = Math.ceil(totalPosts / itemsPerPage);
        const posts = await Post.find(query).populate('userId', 'username').sort({ createdAt: -1 }).skip((page - 1) * itemsPerPage).limit(itemsPerPage);
        res.render('admin/posts', { posts, totalPages, currentPage: page, layout: 'admin/layout' });
    } catch (err) { next(err); }
});

// --- GESTIÓN DE RETIROS (EXISTENTE) ---
app.get('/admin/withdrawals', requireAdmin, async (req, res, next) => {
    try {
        const withdrawals = await Withdrawal.find().populate('userId', 'username email').sort({ createdAt: -1 });
        res.render('admin/withdrawals', { withdrawals, layout: 'admin/layout' });
    } catch (err) { next(err); }
});

app.post('/admin/withdrawal/:id/update', requireAdmin, async (req, res, next) => {
    try {
        const { status } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal) return res.status(404).send('Solicitud no encontrada');
        if (withdrawal.status === 'Pendiente' && status === 'Rechazado') {
            const tpysToReturn = Math.floor(withdrawal.amount / 100);
            await User.findByIdAndUpdate(withdrawal.userId, { $inc: { tpysBalance: tpysToReturn } });
        }
        withdrawal.status = status;
        await withdrawal.save();
        res.redirect('/admin/withdrawals');
    } catch (err) { next(err); }
});

// =============================================
// MANEJADORES DE ERRORES Y ARRANQUE DEL SERVIDOR
// =============================================
app.use((req, res, next) => { res.status(404).render('error', { message: 'Página no encontrada (404)', layout: false }); });

app.use((err, req, res, next) => {
  console.error("❌ ERROR CAPTURADO:", err);
  const status = err.status || 500;
  const message = err.message || 'Ocurrió un error inesperado en el servidor.';
  res.status(status).render('error', { message, layout: false });
});

app.listen(PORT, () => console.log(`🚀 Servidor TentacionPY corriendo en http://localhost:${PORT}`));


// =============================================
//               FIN DEL ARCHIVO
// =============================================
