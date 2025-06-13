<?php
session_start();
$conn = new mysqli("localhost", "root", "Mysql@12345", "blog");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

function sanitize_input($data) {
    return htmlspecialchars(trim($data));
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Server-side validation & sanitization
    $username = isset($_POST['username']) ? sanitize_input($_POST['username']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';

    $errors = [];

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
        // Prepared statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();

        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                $_SESSION['user'] = $user['username'];
                header("Location: dashboard.php");
                exit;
            } else {
                $errors[] = "Invalid password!";
            }
        } else {
            $errors[] = "User not found!";
        }

        $stmt->close();
    }
}

$conn->close();
?>

<h2>Login</h2>

<?php
if (!empty($errors)) {
    echo '<ul style="color:red;">';
    foreach ($errors as $error) {
        echo '<li>' . htmlspecialchars($error) . '</li>';
    }
    echo '</ul>';
}
?>

<form method="POST" onsubmit="return validateForm()">
    Username: <input type="text" name="username" id="username" required><br><br>
    Password: <input type="password" name="password" id="password" required><br><br>
    <button type="submit">Login</button>
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
        return false; // Prevent form submission
    }

    return true; // Allow form submission
}
</script>
