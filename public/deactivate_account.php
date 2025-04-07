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

// Handle deactivation confirmation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        redirectWithMessage('profile.php', 'error', 'Invalid CSRF token');
    }

    // Verify password
    $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (!password_verify($_POST['password'], $user['password'])) {
        redirectWithMessage('deactivate_account.php', 'error', 'Incorrect password');
    }

    // Soft delete user (mark as inactive)
    $stmt = $conn->prepare("UPDATE users SET active = 0 WHERE id = ?");
    $stmt->bind_param("i", $user_id);

    if ($stmt->execute()) {
        logAction($_SESSION['user']['username'], "Account deactivated");
        session_destroy();
        redirectWithMessage('login.php', 'success', 'Your account has been deactivated');
    } else {
        redirectWithMessage('profile.php', 'error', 'Failed to deactivate account');
    }
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deactivate Account | FEU Roosevelt</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-50">
    <div class="min-h-screen flex items-center justify-center">
        <div class="bg-white rounded-lg shadow-lg p-8 w-full max-w-md">
            <div class="text-center mb-6">
                <i class="fas fa-exclamation-triangle text-red-500 text-5xl mb-4"></i>
                <h1 class="text-2xl font-bold text-gray-800">Deactivate Account</h1>
            </div>

            <?php if ($flash): ?>
                <div class="mb-6 p-4 rounded <?= $flash['type'] === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800' ?>">
                    <?= $flash['message'] ?>
                </div>
            <?php endif; ?>

            <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-6">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i class="fas fa-info-circle text-red-500"></i>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm text-red-700">
                            This action will permanently deactivate your account. You will not be able to:
                            <ul class="list-disc list-inside mt-2 text-sm text-red-700">
                                <li>Access the Dean's List portal</li>
                                <li>Submit or view documents</li>
                                <li>Recover your data</li>
                            </ul>
                        </p>
                    </div>
                </div>
            </div>

            <form method="POST" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">

                <div>
                    <label class="block text-gray-700 mb-2">Confirm Password</label>
                    <input type="password" name="password" required
                           class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>

                <div class="flex justify-between">
                    <a href="profile.php" class="px-4 py-2 border rounded text-gray-700 hover:bg-gray-100">
                        Cancel
                    </a>
                    <button type="submit" class="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                        Confirm Deactivation
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>