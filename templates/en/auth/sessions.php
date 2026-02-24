<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sessions &amp; Devices</title>
</head>
<body>
<main>
    <h1>Sessions &amp; Devices</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <?php if (empty($sessions)): ?>
        <p>No active sessions found.</p>
    <?php else: ?>
        <ul>
            <?php foreach ($sessions as $session): ?>
                <li>
                    <strong>Session <?php echo $e((string) ($session['session_hint'] ?? '')); ?></strong>
                    <?php if (($session['is_current'] ?? false) === true): ?>
                        <span>(Current)</span>
                    <?php endif; ?>
                    <div>IP: <?php echo $e((string) (($session['ip_address'] ?? '') !== '' ? $session['ip_address'] : 'Unknown')); ?></div>
                    <div>Last seen: <?php echo $e((string) ($session['last_seen_at'] ?? '')); ?></div>
                    <div>Created: <?php echo $e((string) ($session['created_at'] ?? '')); ?></div>
                    <form method="post" action="/ui/sessions/revoke" novalidate>
                        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">
                        <input type="hidden" name="session_id" value="<?php echo $e((string) ($session['session_id'] ?? '')); ?>">
                        <button type="submit">Revoke Session</button>
                    </form>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</main>
</body>
</html>
