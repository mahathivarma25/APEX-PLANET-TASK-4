<?php
session_start();

// Connect to the database
$conn = new mysqli("localhost", "root", "Mysql@12345", "blog");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

function sanitize_input($data) {
    return htmlspecialchars(trim($data));
}

$message = "";
$message_type = "error"; // to differentiate error/success messages

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize inputs
    $username = isset($_POST['username']) ? sanitize_input($_POST['username']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';

    $errors = [];

    // Server-side validation
    if (empty($username)) {
        $errors[] = "Username is required.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        $errors[] = "Username must be 3-20 characters, letters, numbers, or underscore only.";
    }

    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (strlen($password) < 6) {
        $errors[] = "Password must be at least 6 characters.";
    }

    if (empty($errors)) {
        // Check if username exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $errors[] = "Username already exists!";
        }
        $stmt->close();
    }

    if (empty($errors)) {
        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insert new user
        $insert_stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $insert_stmt->bind_param("ss", $username, $hashed_password);

        if ($insert_stmt->execute()) {
            $message_type = "success";
            $message = "Registered successfully! <a href='login.php'>Click here to login</a>";
        } else {
            $errors[] = "Error while registering. Please try again.";
        }

        $insert_stmt->close();
    }

    if (!empty($errors)) {
        $message = implode("<br>", array_map('htmlspecialchars', $errors));
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Registration</title>
</head>
<body>
    <h2>Register</h2>
    <?php if ($message): ?>
        <p style="color: <?php echo $message_type === 'success' ? 'green' : 'red'; ?>">
            <?php echo $message; ?>
        </p>
    <?php endif; ?>

    <form method="POST" onsubmit="return validateForm()">
        <label>Username:</label><br>
        <input type="text" name="username" id="username" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" id="password" required><br><br>

        <button type="submit">Register</button>
    </form>

    <script>
    function validateForm() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        let errors = [];

        if (username === '') {
            errors.push("Username is required.");
        } else if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
            errors.push("Username must be 3-20 characters, letters, numbers, or underscore only.");
        }

        if (password === '') {
            errors.push("Password is required.");
        } else if (password.length < 6) {
            errors.push("Password must be at least 6 characters.");
        }

        if (errors.length > 0) {
            alert(errors.join("\n"));
            return false;
        }
        return true;
    }
    </script>
</body>
</html>
