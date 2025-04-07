<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

if (isLoggedIn()) {
    $user = $_SESSION['user'];
    header("Location: " . ($user['role'] === 'Dean' ? 'dean_dashboard.php' : ($user['role'] === 'Registrar' ? 'registrar_dashboard.php' : 'view_documents.php')));
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['username']);
    $password = sanitizeInput($_POST['password']);
    $role = sanitizeInput($_POST['role']);
    
    if (!validateCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token';
    } elseif (login($username, $password)) {
        logAction($username, "User logged in");
        exit; // Redirect handled by login() function
    } else {
        $error = 'Invalid username or password';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FEU Roosevelt - Dean's List Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="styles/login.css">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center bg-[url('https://images.pexels.com/photos/207692/pexels-photo-207692.jpeg')] bg-cover bg-center">
        <div class="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
            <h1 class="text-2xl font-bold text-center mb-6 text-blue-800">Dean's List Portal</h1>
            <?php if ($error): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    <?= $error ?>
                </div>
            <?php endif; ?>
            <form method="POST" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                <div>
                    <label class="block text-gray-700 mb-2">Username</label>
                    <input type="text" name="username" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-gray-700 mb-2">Password</label>
                    <input type="password" name="password" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-gray-700 mb-2">Role</label>
                    <select name="role" required class="w-full px-3 py-2 border rounded">
                        <option value="Student">Student</option>
                        <option value="Dean">Dean</option>
                        <option value="Registrar">Registrar</option>
                    </select>
                </div>
                <button type="submit" 
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                    Login
                </button>
            </form>
            <div class="mt-4 text-center">
                <a href="register.php" class="text-blue-600 hover:underline">Create an account</a>
            </div>
        </div>
    </div>
</body>
</html>