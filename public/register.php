<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Only allow registration if not logged in
if (isLoggedIn()) {
    $user = $_SESSION['user'];
    header("Location: " . ($user['role'] === 'Dean' ? 'dean_dashboard.php' : ($user['role'] === 'Registrar' ? 'registrar_dashboard.php' : 'view_documents.php')));
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['username']);
    $password = password_hash(sanitizeInput($_POST['password']), PASSWORD_BCRYPT);
    $email = sanitizeInput($_POST['email']);
    $role = sanitizeInput($_POST['role']);

    if (!validateCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token';
    } else {
        try {
            $conn = new mysqli('localhost', 'root', '', 'deans_list');
            $stmt = $conn->prepare("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $username, $password, $email, $role);
            
            if ($stmt->execute()) {
                logAction($username, "New account created");
                $success = 'Registration successful! Please login.';
                $_POST = []; // Clear form
            } else {
                $error = 'Username or email already exists';
            }
        } catch (Exception $e) {
            $error = 'Registration failed: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | FEU Roosevelt</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="styles/register.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center bg-[url('https://images.pexels.com/photos/1438081/pexels-photo-1438081.jpeg')] bg-cover bg-center">
        <div class="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
            <div class="flex justify-center mb-6">
                <i class="fas fa-user-graduate text-4xl text-blue-600"></i>
            </div>
            <h1 class="text-2xl font-bold text-center mb-6 text-blue-800">Create Account</h1>
            
            <?php if ($error): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    <?= $error ?>
                </div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
                    <?= $success ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                
                <div>
                    <label class="block text-gray-700 mb-2">Username</label>
                    <input type="text" name="username" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                           value="<?= $_POST['username'] ?? '' ?>">
                </div>
                
                <div>
                    <label class="block text-gray-700 mb-2">Email</label>
                    <input type="email" name="email" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                           value="<?= $_POST['email'] ?? '' ?>">
                </div>
                
                <div>
                    <label class="block text-gray-700 mb-2">Password</label>
                    <input type="password" name="password" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                
                <div>
                    <label class="block text-gray-700 mb-2">Confirm Password</label>
                    <input type="password" name="confirm_password" required 
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                
                <div>
                    <label class="block text-gray-700 mb-2">Role</label>
                    <select name="role" required class="w-full px-3 py-2 border rounded">
                        <option value="Student" <?= ($_POST['role'] ?? '') === 'Student' ? 'selected' : '' ?>>Student</option>
                        <option value="Dean" <?= ($_POST['role'] ?? '') === 'Dean' ? 'selected' : '' ?>>Dean</option>
                        <option value="Registrar" <?= ($_POST['role'] ?? '') === 'Registrar' ? 'selected' : '' ?>>Registrar</option>
                    </select>
                </div>
                
                <button type="submit" 
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition duration-200">
                    Register
                </button>
            </form>
            
            <div class="mt-4 text-center">
                <a href="login.php" class="text-blue-600 hover:underline">Already have an account? Login</a>
            </div>
        </div>
    </div>
</body>
</html>