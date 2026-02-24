<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Request Password Reset</title>
</head>
<body>
<main>
    <h1>Request Password Reset</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/password-reset/request" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="identifier">Username or Email</label>
        <input id="identifier" name="identifier" type="text" required>

        <button type="submit">Send reset instructions</button>
    </form>
</main>
</body>
</html>
