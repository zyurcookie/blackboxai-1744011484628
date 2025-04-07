<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Secure access - only for logged-in deans
if (!isLoggedIn() || $_SESSION['user']['role'] !== 'Dean') {
    header("Location: login.php");
    exit;
}

$conn = new mysqli('localhost', 'root', '', 'deans_list');

// Handle document approval/decline
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        redirectWithMessage('dean_dashboard.php', 'error', 'Invalid CSRF token');
    }

    $doc_id = $_POST['doc_id'];
    $action = $_POST['action'];
    $reason = sanitizeInput($_POST['reason'] ?? '');

    $status = ($action === 'approve') ? 'Approved' : 'Declined';
    $stmt = $conn->prepare("UPDATE documents SET status = ?, approval_reason = ? WHERE id = ?");
    $stmt->bind_param("ssi", $status, $reason, $doc_id);

    if ($stmt->execute()) {
        $action_text = ($action === 'approve') ? 'approved' : 'declined';
        logAction($_SESSION['user']['username'], "Document $doc_id $action_text");
        redirectWithMessage('dean_dashboard.php', 'success', "Document $action_text successfully");
    } else {
        redirectWithMessage('dean_dashboard.php', 'error', 'Failed to update document status');
    }
}

// Get pending documents with student info
$query = "SELECT d.id, d.filename, d.upload_date, u.username as student_name 
          FROM documents d 
          JOIN users u ON d.user_id = u.id 
          WHERE d.status = 'Pending' 
          ORDER BY d.upload_date ASC";
$pending_docs = $conn->query($query)->fetch_all(MYSQLI_ASSOC);

// Get recently processed documents
$query = "SELECT d.id, d.filename, d.status, d.upload_date, d.approval_reason, u.username as student_name 
          FROM documents d 
          JOIN users u ON d.user_id = u.id 
          WHERE d.status != 'Pending' 
          ORDER BY d.upload_date DESC 
          LIMIT 10";
$processed_docs = $conn->query($query)->fetch_all(MYSQLI_ASSOC);

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dean's Dashboard | FEU Roosevelt</title>
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
                    <span class="font-medium"><?= $_SESSION['user']['username'] ?> (Dean)</span>
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

            <h2 class="text-2xl font-bold text-gray-800 mb-6">Pending Document Reviews</h2>

            <?php if (empty($pending_docs)): ?>
                <div class="bg-white rounded-lg shadow p-6 text-center">
                    <i class="fas fa-check-circle text-green-500 text-5xl mb-4"></i>
                    <h3 class="text-xl font-medium text-gray-800 mb-2">No pending documents</h3>
                    <p class="text-gray-600">All documents have been reviewed.</p>
                </div>
            <?php else: ?>
                <div class="bg-white rounded-lg shadow overflow-hidden mb-8">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Student</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Submitted</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($pending_docs as $doc): ?>
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
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <button onclick="openModal('<?= $doc['id'] ?>', 'approve')" 
                                                class="text-green-600 hover:text-green-900 mr-3">
                                            <i class="fas fa-check-circle"></i> Approve
                                        </button>
                                        <button onclick="openModal('<?= $doc['id'] ?>', 'decline')" 
                                                class="text-red-600 hover:text-red-900">
                                            <i class="fas fa-times-circle"></i> Decline
                                        </button>
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

            <h2 class="text-2xl font-bold text-gray-800 mb-6">Recently Processed Documents</h2>
            <div class="bg-white rounded-lg shadow overflow-hidden">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Student</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Processed</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($processed_docs as $doc): ?>
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
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?= getDocumentStatusBadge($doc['status']) ?>
                                    <?php if ($doc['status'] === 'Declined' && !empty($doc['approval_reason'])): ?>
                                        <p class="text-xs text-gray-500 mt-1">Reason: <?= htmlspecialchars($doc['approval_reason']) ?></p>
                                    <?php endif; ?>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    <?= date('M d, Y h:i A', strtotime($doc['upload_date'])) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>

    <!-- Approval/Decline Modal -->
    <div id="actionModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden flex items-center justify-center">
        <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
            <h3 id="modalTitle" class="text-xl font-bold mb-4"></h3>
            <form id="actionForm" method="POST">
                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                <input type="hidden" id="docId" name="doc_id">
                <input type="hidden" id="actionType" name="action">
                <div id="reasonField" class="mb-4 hidden">
                    <label for="reason" class="block text-gray-700 mb-2">Reason for Decline</label>
                    <textarea id="reason" name="reason" rows="3" class="w-full px-3 py-2 border rounded"></textarea>
                </div>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeModal()" class="px-4 py-2 border rounded text-gray-700 hover:bg-gray-100">
                        Cancel
                    </button>
                    <button type="submit" class="px-4 py-2 rounded text-white" id="submitBtn">
                        Confirm
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
    function openModal(docId, action) {
        const modal = document.getElementById('actionModal');
        const title = document.getElementById('modalTitle');
        const reasonField = document.getElementById('reasonField');
        const submitBtn = document.getElementById('submitBtn');
        const actionType = document.getElementById('actionType');
        const docIdInput = document.getElementById('docId');

        docIdInput.value = docId;
        actionType.value = action;

        if (action === 'approve') {
            title.textContent = 'Approve Document';
            reasonField.classList.add('hidden');
            submitBtn.textContent = 'Approve';
            submitBtn.className = 'px-4 py-2 rounded text-white bg-green-600 hover:bg-green-700';
        } else {
            title.textContent = 'Decline Document';
            reasonField.classList.remove('hidden');
            submitBtn.textContent = 'Decline';
            submitBtn.className = 'px-4 py-2 rounded text-white bg-red-600 hover:bg-red-700';
        }

        modal.classList.remove('hidden');
    }

    function closeModal() {
        document.getElementById('actionModal').classList.add('hidden');
    }
    </script>
</body>
</html>