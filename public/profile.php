<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

if (!isLoggedIn()) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user']['id'];
$conn = new mysqli('localhost', 'root', '', 'deans_list');

// Handle profile updates
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        redirectWithMessage('profile.php', 'error', 'Invalid CSRF token');
    }

    $email = sanitizeInput($_POST['email']);
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];

    // Verify current password
    $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (!password_verify($current_password, $user['password'])) {
        redirectWithMessage('profile.php', 'error', 'Current password is incorrect');
    }

    // Update profile
    if (!empty($new_password)) {
        $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("UPDATE users SET email = ?, password = ? WHERE id = ?");
        $stmt->bind_param("ssi", $email, $hashed_password, $user_id);
    } else {
        $stmt = $conn->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->bind_param("si", $email, $user_id);
    }

    if ($stmt->execute()) {
        logAction($_SESSION['user']['username'], "Profile updated");
        redirectWithMessage('profile.php', 'success', 'Profile updated successfully');
    } else {
        redirectWithMessage('profile.php', 'error', 'Failed to update profile');
    }
}

// Get user data
$stmt = $conn->prepare("SELECT username, email, dean_list FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile | FEU Roosevelt</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="styles/profile.css">
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-blue-700 text-white shadow-md">
            <div class="container mx-auto px-4 py-3 flex justify-between items-center">
                <h1 class="text-xl font-bold">Dean's List Portal</h1>
                <div class="flex items-center space-x-4">
                    <span class="font-medium"><?= $_SESSION['user']['username'] ?></span>
                    <a href="../includes/auth.php?logout" class="hover:text-blue-200">
                        <i class="fas fa-sign-out-alt"></i>
                    </a>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="container mx-auto px-4 py-6">
            <?php if ($flash): ?>
                <div class="mb-6 p-4 rounded <?= $flash['type'] === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800' ?>">
                    <?= $flash['message'] ?>
                </div>
            <?php endif; ?>

            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold text-gray-800">My Profile</h2>
                <a href="deactivate_account.php" class="text-red-600 hover:text-red-800 text-sm">
                    <i class="fas fa-user-slash mr-1"></i> Deactivate Account
                </a>
            </div>

            <div class="bg-white rounded-lg shadow overflow-hidden p-6">
                <div class="mb-6">
                    <h3 class="text-lg font-medium text-gray-800 mb-2">Account Status</h3>
                    <div class="flex items-center">
                        <span class="px-2 py-1 rounded-full text-xs font-medium <?= $user['dean_list'] ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800' ?>">
                            <?= $user['dean_list'] ? 'Dean\'s List Eligible' : 'Regular Student' ?>
                        </span>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">

                    <div>
                        <label class="block text-gray-700 mb-2">Username</label>
                        <input type="text" value="<?= htmlspecialchars($user['username']) ?>" class="w-full px-3 py-2 border rounded bg-gray-100" disabled>
                    </div>

                    <div>
                        <label class="block text-gray-700 mb-2">Email</label>
                        <input type="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" required
                               class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>

                    <div>
                        <label class="block text-gray-700 mb-2">Current Password</label>
                        <input type="password" name="current_password" required
                               class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>

                    <div>
                        <label class="block text-gray-700 mb-2">New Password (leave blank to keep current)</label>
                        <input type="password" name="new_password"
                               class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>

                    <div class="flex justify-end">
                        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded">
                            Update Profile
                        </button>
                    </div>
                </form>
            </div>
        </main>
    </div>
</body>
</html>