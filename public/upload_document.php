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
$error = '';

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token';
    } elseif (isset($_FILES['document']) && $_FILES['document']['error'] === UPLOAD_ERR_OK) {
        $validation = validateDocument($_FILES['document']);
        if ($validation === true) {
            // Generate unique filename
            $extension = pathinfo($_FILES['document']['name'], PATHINFO_EXTENSION);
            $filename = uniqid('doc_', true) . '.' . $extension;
            $target_path = "../uploaded_files/documents/" . $filename;

            if (move_uploaded_file($_FILES['document']['tmp_name'], $target_path)) {
                // Save to database
                $conn = new mysqli('localhost', 'root', '', 'deans_list');
                $stmt = $conn->prepare("INSERT INTO documents (user_id, filename) VALUES (?, ?)");
                $stmt->bind_param("is", $user_id, $filename);
                
                if ($stmt->execute()) {
                    logAction($_SESSION['user']['username'], "Document uploaded: $filename");
                    redirectWithMessage('view_documents.php', 'success', 'Document uploaded successfully!');
                } else {
                    $error = 'Failed to save document record';
                    unlink($target_path); // Clean up file if DB insert failed
                }
            } else {
                $error = 'Error moving uploaded file';
            }
        } else {
            $error = $validation;
        }
    } else {
        $error = 'No file uploaded or upload error occurred';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Document | FEU Roosevelt</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="styles/upload.css">
    <script src="scripts/upload.js"></script>
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
            <div class="max-w-3xl mx-auto">
                <div class="flex items-center mb-6">
                    <a href="view_documents.php" class="text-blue-600 hover:text-blue-800 mr-2">
                        <i class="fas fa-arrow-left"></i>
                    </a>
                    <h2 class="text-2xl font-bold text-gray-800">Upload New Document</h2>
                </div>

                <?php if ($error): ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
                        <?= $error ?>
                    </div>
                <?php endif; ?>

                <div class="bg-white rounded-lg shadow overflow-hidden p-6">
                    <form id="uploadForm" method="POST" enctype="multipart/form-data" class="space-y-6">
                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">

                        <div class="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center" id="dropZone">
                            <div id="filePreview" class="hidden mb-4">
                                <i class="fas fa-file-pdf text-red-500 text-5xl"></i>
                                <p id="fileName" class="mt-2 font-medium"></p>
                                <p id="fileSize" class="text-sm text-gray-500"></p>
                            </div>
                            <div id="uploadPrompt">
                                <i class="fas fa-cloud-upload-alt text-blue-500 text-5xl mb-3"></i>
                                <p class="text-gray-600 mb-2">Drag & drop your document here</p>
                                <p class="text-sm text-gray-500 mb-4">or</p>
                                <label for="document" class="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded inline-flex items-center">
                                    <i class="fas fa-folder-open mr-2"></i> Select File
                                </label>
                                <input type="file" name="document" id="document" class="hidden" accept=".pdf" required>
                            </div>
                        </div>

                        <div class="text-xs text-gray-500">
                            <p><i class="fas fa-info-circle mr-1"></i> Only PDF files are accepted (max 5MB)</p>
                            <p><i class="fas fa-info-circle mr-1"></i> Documents will be reviewed by the Dean's office</p>
                        </div>

                        <div class="flex justify-end">
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded flex items-center">
                                <i class="fas fa-upload mr-2"></i> Submit Document
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>

    <script>
    // Drag and drop functionality
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('document');
    const filePreview = document.getElementById('filePreview');
    const uploadPrompt = document.getElementById('uploadPrompt');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-blue-500', 'bg-blue-50');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-blue-500', 'bg-blue-50');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-blue-500', 'bg-blue-50');
        
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            updateFilePreview(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            updateFilePreview(fileInput.files[0]);
        }
    });

    function updateFilePreview(file) {
        if (file.type === 'application/pdf') {
            fileName.textContent = file.name;
            fileSize.textContent = formatFileSize(file.size);
            filePreview.classList.remove('hidden');
            uploadPrompt.classList.add('hidden');
        } else {
            alert('Only PDF files are allowed');
            fileInput.value = '';
        }
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    </script>
</body>
</html>