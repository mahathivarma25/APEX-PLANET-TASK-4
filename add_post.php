<?php

// Redirect if not logged in
if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit();
}

// CSRF token setup
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$conn = new mysqli("localhost", "root", "Mysql@12345", "blog");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

function sanitize($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

$edit_mode = false;
$post_id = '';
$title = '';
$content = '';
$message = '';

// Server-side: Add/Update Post
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // CSRF token check
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token.");
    }

    // Sanitize input
    $title = sanitize($_POST['title'] ?? '');
    $content = sanitize($_POST['content'] ?? '');

    // Validation
    if (empty($title) || empty($content)) {
        $message = "All fields are required.";
    } elseif (strlen($title) > 255) {
        $message = "Title is too long (max 255 characters).";
    } else {
        if (!empty($_POST['post_id'])) {
            // Update
            $post_id = (int)$_POST['post_id'];
            $stmt = $conn->prepare("UPDATE post SET title = ?, content = ? WHERE id = ?");
            $stmt->bind_param("ssi", $title, $content, $post_id);
            $stmt->execute();
            $message = $stmt->affected_rows > 0 ? "Post updated successfully!" : "No changes made.";
            $stmt->close();
        } else {
            // Insert
            $stmt = $conn->prepare("INSERT INTO post (title, content) VALUES (?, ?)");
            $stmt->bind_param("ss", $title, $content);
            $stmt->execute();
            $message = "New post added successfully!";
            $stmt->close();
        }
    }
}

// Handle Edit
if (isset($_GET['edit'])) {
    $edit_mode = true;
    $post_id = (int)$_GET['edit'];
    $stmt = $conn->prepare("SELECT title, content FROM post WHERE id = ?");
    $stmt->bind_param("i", $post_id);
    $stmt->execute();
    $stmt->bind_result($title, $content);
    $stmt->fetch();
    $stmt->close();
}

// Handle Delete
if (isset($_GET['delete'])) {
    $delete_id = (int)$_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM post WHERE id = ?");
    $stmt->bind_param("i", $delete_id);
    $stmt->execute();
    $message = "Post deleted successfully!";
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo $edit_mode ? "Edit Post" : "Add New Post"; ?></title>
    <script>
        function validateForm() {
            const title = document.getElementById("title").value.trim();
            const content = document.getElementById("content").value.trim();

            if (title === "" || content === "") {
                alert("Both Title and Content are required.");
                return false;
            }

            if (title.length > 255) {
                alert("Title cannot exceed 255 characters.");
                return false;
            }

            return true;
        }
    </script>
</head>
<body>
    <h2><?php echo $edit_mode ? "Edit Post" : "Add New Post"; ?></h2>
    <?php if ($message): ?>
        <p style="color:green;"><?php echo $message; ?></p>
    <?php endif; ?>

    <form method="POST" onsubmit="return validateForm();">
        <input type="hidden" name="post_id" value="<?php echo sanitize($post_id); ?>">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

        <label for="title">Title:</label><br>
        <input type="text" id="title" name="title" maxlength="255" value="<?php echo sanitize($title); ?>" required><br><br>

        <label for="content">Content:</label><br>
        <textarea id="content" name="content" rows="6" cols="50" required><?php echo sanitize($content); ?></textarea><br><br>

        <input type="submit" value="<?php echo $edit_mode ? "Update Post" : "Add Post"; ?>">
        <?php if ($edit_mode): ?>
            <a href="add_post.php">Cancel</a>
        <?php endif; ?>
    </form>

    <hr>
    <h2>All Posts</h2>

    <?php
    $result = $conn->query("SELECT * FROM post ORDER BY created_at DESC");
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "<div style='border:1px solid #ccc; padding:10px; margin-bottom:10px;'>";
            echo "<h3>" . sanitize($row['title']) . "</h3>";
            echo "<p>" . nl2br(sanitize($row['content'])) . "</p>";
            echo "<small>Posted on: " . sanitize($row['created_at']) . "</small><br>";
            echo "<a href='add_post.php?edit=" . (int)$row['id'] . "'>Edit</a> | ";
            echo "<a href='add_post.php?delete=" . (int)$row['id'] . "' onclick='return confirm(\"Are you sure?\");'>Delete</a>";
            echo "</div>";
        }
    } else {
        echo "<p>No posts found.</p>";
    }

    $conn->close();
    ?>
</body>
</html>
