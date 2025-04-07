<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Secure access - only for logged-in registrars
if (!isLoggedIn() || $_SESSION['user']['role'] !== 'Registrar') {
    header("Location: login.php");
    exit;
}

$conn = new mysqli('localhost', 'root', '', 'deans_list');

// Handle final verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        redirectWithMessage('registrar_dashboard.php', 'error', 'Invalid CSRF token');
    }

    $doc_id = $_POST['doc_id'];
    $action = $_POST['action'];
    $status = ($action === 'confirm') ? 'Confirmed' : 'Pending'; // Revert to pending if rejected

    $stmt = $conn->prepare("UPDATE documents SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $status, $doc_id);

    if ($stmt->execute()) {
        $action_text = ($action === 'confirm') ? 'confirmed' : 'returned for review';
        logAction($_SESSION['user']['username'], "Document $doc_id $action_text");
        
        // If confirmed, update student's dean's list status
        if ($action === 'confirm') {
            $stmt = $conn->prepare("UPDATE users SET dean_list = 1 WHERE id = (SELECT user_id FROM documents WHERE id = ?)");
            $stmt->bind_param("i", $doc_id);
            $stmt->execute();
        }
        
        redirectWithMessage('registrar_dashboard.php', 'success', "Document $action_text successfully");
    } else {
        redirectWithMessage('registrar_dashboard.php', 'error', 'Failed to update document status');
    }
}

// Get dean-approved documents with student info
$query = "SELECT d.id, d.filename, d.upload_date, u.username as student_name, u.email 
          FROM documents d 
          JOIN users u ON d.user_id = u.id 
          WHERE d.status = 'Approved' 
          ORDER BY d.upload_date ASC";
$approved_docs = $conn->query($query)->fetch_all(MYSQLI_ASSOC);

// Get recently confirmed documents
$query = "SELECT d.id, d.filename, d.upload_date, u.username as student_name 
          FROM documents d 
          JOIN users u ON d.user_id = u.id 
          WHERE d.status = 'Confirmed' 
          ORDER BY d.upload_date DESC 
          LIMIT 10";
$confirmed_docs = $conn->query($query)->fetch_all(MYSQLI_ASSOC);

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrar's Dashboard | FEU Roosevelt</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="styles/dashboard.css">
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-blue-700 text-white shadow-md">
            <div class="container mx-auto px-4 py-3 flex justify-between items-center">
                <h1 class="text-xl font-bold">Dean's List Portal</h1>
                <div class="flex items-center space-x-4">
                    <span class="font-medium"><?= $_SESSION['user']['username'] ?> (Registrar)</span>
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

            <h2 class="text-2xl font-bold text-gray-800 mb-6">Documents Ready for Final Verification</h2>

            <?php if (empty($approved_docs)): ?>
                <div class="bg-white rounded-lg shadow p-6 text-center">
                    <i class="fas fa-check-circle text-green-500 text-5xl mb-4"></i>
                    <h3 class="text-xl font-medium text-gray-800 mb-2">No documents pending verification</h3>
                    <p class="text-gray-600">All approved documents have been processed.</p>
                </div>
            <?php else: ?>
                <div class="bg-white rounded-lg shadow overflow-hidden mb-8">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Student</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Approved</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($approved_docs as $doc): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900"><?= htmlspecialchars($doc['student_name']) ?></div>
                                        <div class="text-xs text-gray-500"><?= htmlspecialchars($doc['email']) ?></div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <i class="fas fa-file-pdf text-red-500 mr-2"></i>
                                            <span class="text-sm font-medium text-gray-900"><?= htmlspecialchars($doc['filename']) ?></span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        <?= date('M d, Y h:i A', strtotime($doc['upload_date'])) ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <form method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                            <input type="hidden" name="doc_id" value="<?= $doc['id'] ?>">
                                            <input type="hidden" name="action" value="confirm">
                                            <button type="submit" 
                                                    class="text-green-600 hover:text-green-900 mr-3">
                                                <i class="fas fa-check-circle"></i> Confirm Eligibility
                                            </button>
                                        </form>
                                        <form method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                            <input type="hidden" name="doc_id" value="<?= $doc['id'] ?>">
                                            <input type="hidden" name="action" value="return">
                                            <button type="submit" 
                                                    class="text-yellow-600 hover:text-yellow-900">
                                                <i class="fas fa-undo"></i> Return for Review
                                            </button>
                                        </form>
                                        <a href="../uploaded_files/documents/<?= $doc['filename'] ?>" 
                                           target="_blank" 
                                           class="text-blue-600 hover:text-blue-900 ml-3">
                                            <i class="fas fa-eye"></i> View
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>

            <h2 class="text-2xl font-bold text-gray-800 mb-6">Recently Confirmed Documents</h2>
            <div class="bg-white rounded-lg shadow overflow-hidden">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Student</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Confirmed</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($confirmed_docs as $doc): ?>
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm font-medium text-gray-900"><?= htmlspecialchars($doc['student_name']) ?></div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center">
                                        <i class="fas fa-file-pdf text-red-500 mr-2"></i>
                                        <span class="text-sm font-medium text-gray-900"><?= htmlspecialchars($doc['filename']) ?></span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    <?= date('M d, Y h:i A', strtotime($doc['upload_date'])) ?>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?= getDocumentStatusBadge('Confirmed') ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>
</body>
</html>