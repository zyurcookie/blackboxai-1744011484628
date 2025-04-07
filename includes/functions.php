<?php
function validateDocument($file) {
    $allowedTypes = ['application/pdf'];
    if (!in_array($file['type'], $allowedTypes)) {
        return "Only PDF files are allowed.";
    }
    if ($file['size'] > 5 * 1024 * 1024) {
        return "File size exceeds 5MB limit.";
    }
    return true;
}

function sanitizeInput($input) {
    global $conn;
    return mysqli_real_escape_string($conn, htmlspecialchars(trim($input)));
}

function logAction($user, $action) {
    global $conn;
    $stmt = $conn->prepare("INSERT INTO logs (user, action) VALUES (?, ?)");
    $stmt->bind_param("ss", $user, $action);
    $stmt->execute();
}

function getDocumentStatusBadge($status) {
    $badges = [
        'Pending' => 'bg-yellow-100 text-yellow-800',
        'Approved' => 'bg-green-100 text-green-800',
        'Declined' => 'bg-red-100 text-red-800',
        'Confirmed' => 'bg-blue-100 text-blue-800'
    ];
    return '<span class="px-2 py-1 rounded-full text-xs font-medium '.$badges[$status].'">'.$status.'</span>';
}

function redirectWithMessage($url, $type, $message) {
    $_SESSION['flash'] = [
        'type' => $type,
        'message' => $message
    ];
    header("Location: $url");
    exit;
}
?>