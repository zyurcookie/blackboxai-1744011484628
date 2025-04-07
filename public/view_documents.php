<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Secure access - only for logged-in students
if (!isLoggedIn() || $_SESSION['user']['role'] !== 'Student') {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user']['id'];
$conn = new mysqli('localhost', 'root', '', 'deans_list');

// Get student's documents
$stmt = $conn->prepare("SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$documents = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Handle flash messages
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Documents | FEU Roosevelt</title>
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
                <h2 class="text-2xl font-bold text-gray-800">My Document Submissions</h2>
                <a href="upload_document.php" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center">
                    <i class="fas fa-plus mr-2"></i> New Submission
                </a>
            </div>

            <div class="bg-white rounded-lg shadow overflow-hidden">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Submitted</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php if (empty($documents)): ?>
                            <tr>
                                <td colspan="4" class="px-6 py-4 text-center text-gray-500">No documents submitted yet</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($documents as $doc): ?>
                                <tr>
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
                                        <?= getDocumentStatusBadge($doc['status']) ?>
                                        <?php if ($doc['status'] === 'Declined' && !empty($doc['approval_reason'])): ?>
                                            <p class="text-xs text-gray-500 mt-1">Reason: <?= htmlspecialchars($doc['approval_reason']) ?></p>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <a href="../uploaded_files/documents/<?= $doc['filename'] ?>" 
                                           class="text-blue-600 hover:text-blue-900 mr-3" 
                                           target="_blank" 
                                           download>
                                            <i class="fas fa-download"></i> Download
                                        </a>
                                        <a href="#" class="text-red-600 hover:text-red-900" onclick="confirmDelete('<?= $doc['id'] ?>')">
                                            <i class="fas fa-trash"></i> Delete
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>

    <script>
    function confirmDelete(docId) {
        if (confirm('Are you sure you want to delete this submission?')) {
            window.location.href = `delete_document.php?id=${docId}`;
        }
    }
    </script>
</body>
</html>