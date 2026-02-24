<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Passkeys</title>
</head>
<body>
<main>
    <h1>Passkeys</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <?php if (empty($credentials)): ?>
        <p>No passkeys are currently registered.</p>
    <?php else: ?>
        <ul>
            <?php foreach ($credentials as $credential): ?>
                <li>
                    <strong><?php echo $e((string) (($credential['label'] ?? '') !== '' ? $credential['label'] : 'Unnamed passkey')); ?></strong>
                    <div>Created: <?php echo $e((string) ($credential['created_at'] ?? '')); ?></div>
                    <div>Last used: <?php echo $e((string) ($credential['last_used_at'] ?? 'Never')); ?></div>
                    <form method="post" action="/ui/passkeys/revoke" novalidate>
                        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">
                        <input type="hidden" name="credential_id" value="<?php echo $e((string) ($credential['credential_id'] ?? '')); ?>">
                        <button type="submit">Revoke</button>
                    </form>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</main>
</body>
</html>
