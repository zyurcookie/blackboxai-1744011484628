<?php
// Database connection file
$host = 'localhost';
$user = 'root';
$pass = '';
$db = 'deans_list';

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create tables if not exists
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(255),
    role ENUM('Dean', 'Registrar', 'Student') DEFAULT 'Student',
    email VARCHAR(100) UNIQUE
)";
$conn->query($sql);

$sql = "CREATE TABLE IF NOT EXISTS documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    filename VARCHAR(255),
    status ENUM('Pending', 'Approved', 'Declined', 'Confirmed') DEFAULT 'Pending',
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approval_reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)";
$conn->query($sql);

$sql = "CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user VARCHAR(50),
    action TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
$conn->query($sql);

$conn->close();
?>