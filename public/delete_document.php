<?php
require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Secure access - only for logged-in users
if (!isLoggedIn()) {
    header("Location: login.php");
    exit;
}

// Check if document ID is provided
if (!isset($_GET['id'])) {
    redirectWithMessage('view_documents.php', 'error', 'No document specified');
}

$doc_id = intval($_GET['id']);
$user_id = $_SESSION['user']['id'];
$conn = new mysqli('localhost', 'root', '', 'deans_list');

// Verify document ownership (students) or admin role
$query = "SELECT d.filename, d.user_id, u.role 
          FROM documents d 
          JOIN users u ON d.user_id = u.id 
          WHERE d.id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $doc_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    redirectWithMessage('view_documents.php', 'error', 'Document not found');
}

$document = $result->fetch_assoc();

// Authorization check
$is_owner = ($document['user_id'] === $user_id);
$is_admin = in_array($_SESSION['user']['role'], ['Dean', 'Registrar']);

if (!$is_owner && !$is_admin) {
    redirectWithMessage('view_documents.php', 'error', 'Unauthorized action');
}

// Proceed with deletion
try {
    // Delete file from storage
    $file_path = "../uploaded_files/documents/" . $document['filename'];
    if (file_exists($file_path)) {
        unlink($file_path);
    }

    // Delete record from database
    $stmt = $conn->prepare("DELETE FROM documents WHERE id = ?");
    $stmt->bind_param("i", $doc_id);
    $stmt->execute();

    // Log the action
    $action = "Document deleted: " . $document['filename'];
    logAction($_SESSION['user']['username'], $action);

    redirectWithMessage('view_documents.php', 'success', 'Document deleted successfully');
} catch (Exception $e) {
    redirectWithMessage('view_documents.php', 'error', 'Failed to delete document: ' . $e->getMessage());
}
?>