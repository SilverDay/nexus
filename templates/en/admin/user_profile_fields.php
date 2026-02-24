<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin: User Profile Fields</title>
</head>
<body>
<main>
    <h1>Admin: User Profile Fields</h1>

    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <?php if (!empty($user)): ?>
        <section>
            <h2>User</h2>
            <p><strong>ID:</strong> <?php echo $e((string) ($user['id'] ?? '')); ?></p>
            <p><strong>Username:</strong> <?php echo $e((string) ($user['username'] ?? '')); ?></p>
            <p><strong>Email:</strong> <?php echo $e((string) ($user['email'] ?? '')); ?></p>
            <p><strong>Real name:</strong> <?php echo $e((string) ($user['real_name'] ?? '')); ?></p>
            <p><strong>Status:</strong> <?php echo $e((string) ($user['status'] ?? '')); ?></p>
        </section>

        <section>
            <h2>Search</h2>
            <form method="get" action="/ui/admin/user/profile-fields" novalidate>
                <input type="hidden" name="target_user_id" value="<?php echo $e((string) ($user['id'] ?? '')); ?>">

                <label for="q">Search profile fields</label>
                <input id="q" name="q" type="text" value="<?php echo $e((string) ($query ?? '')); ?>">

                <label for="limit">Page size</label>
                <input id="limit" name="limit" type="number" min="1" max="200" value="<?php echo $e((string) ($limit ?? 50)); ?>">

                <button type="submit">Apply</button>
            </form>
        </section>

        <section>
            <h2>Admin-visible Profile Fields (read-only)</h2>
            <p>Total matching fields: <?php echo $e((string) ($total ?? 0)); ?></p>
            <ul>
                <?php foreach (($profileFields ?? []) as $entry): ?>
                    <li>
                        <strong><?php echo $e((string) ($entry['label'] ?? ($entry['field_key'] ?? 'field'))); ?>:</strong>
                        <?php echo $e((string) ($entry['value'] ?? '')); ?>
                    </li>
                <?php endforeach; ?>
            </ul>

            <?php
            $currentOffset = (int) ($offset ?? 0);
            $currentLimit = max(1, (int) ($limit ?? 50));
            $currentTotal = (int) ($total ?? 0);
            $targetUserId = (int) ($user['id'] ?? 0);
            $queryString = (string) ($query ?? '');
            $prevOffset = max(0, $currentOffset - $currentLimit);
            $nextOffset = $currentOffset + $currentLimit;
            ?>

            <nav aria-label="Pagination">
                <?php if ($currentOffset > 0): ?>
                    <a href="/ui/admin/user/profile-fields?target_user_id=<?php echo $e((string) $targetUserId); ?>&amp;q=<?php echo urlencode($queryString); ?>&amp;limit=<?php echo $e((string) $currentLimit); ?>&amp;offset=<?php echo $e((string) $prevOffset); ?>">Previous</a>
                <?php endif; ?>

                <?php if ($nextOffset < $currentTotal): ?>
                    <a href="/ui/admin/user/profile-fields?target_user_id=<?php echo $e((string) $targetUserId); ?>&amp;q=<?php echo urlencode($queryString); ?>&amp;limit=<?php echo $e((string) $currentLimit); ?>&amp;offset=<?php echo $e((string) $nextOffset); ?>">Next</a>
                <?php endif; ?>
            </nav>
        </section>
    <?php else: ?>
        <p>User not found.</p>
    <?php endif; ?>
</main>
</body>
</html>
