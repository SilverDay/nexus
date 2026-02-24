<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AdminUserServiceInterface;
use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class AdminUserService implements AdminUserServiceInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly PDO $pdo,
        private readonly RoleRepositoryInterface $roles,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function listUsers(int $actorUserId, string $query = '', int $limit = 50, int $offset = 0): array
    {
        $this->assertAdmin($actorUserId);

        $safeLimit = max(1, min($limit, 100));
        $safeOffset = max(0, $offset);

        $where = 'deleted_at IS NULL';
        $params = [];
        if (trim($query) !== '') {
            $where .= ' AND (username LIKE :q OR email LIKE :q OR real_name LIKE :q)';
            $params['q'] = '%' . $query . '%';
        }

        $countSql = 'SELECT COUNT(*) FROM users WHERE ' . $where;
        $countStmt = $this->pdo->prepare($countSql);
        $countStmt->execute($params);
        $total = (int) $countStmt->fetchColumn();

        $listSql = 'SELECT id, username, email, real_name, status, email_verified_at, created_at
                    FROM users
                    WHERE ' . $where . '
                    ORDER BY id DESC
                    LIMIT :limit OFFSET :offset';
        $listStmt = $this->pdo->prepare($listSql);
        foreach ($params as $key => $value) {
            $listStmt->bindValue($key, $value, PDO::PARAM_STR);
        }
        $listStmt->bindValue('limit', $safeLimit, PDO::PARAM_INT);
        $listStmt->bindValue('offset', $safeOffset, PDO::PARAM_INT);
        $listStmt->execute();

        $items = $listStmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($items as &$item) {
            if (isset($item['id'])) {
                $userId = (int) $item['id'];
                $item['roles'] = $this->roles->rolesForUser($userId);
                $item['profile_fields_url'] = '/admin/user/profile-fields?target_user_id=' . $userId;
                $item['profile_fields_ui_url'] = '/ui/admin/user/profile-fields?target_user_id=' . $userId;
            }
        }

        return ['items' => is_array($items) ? $items : [], 'total' => $total];
    }

    public function updateUser(int $actorUserId, int $targetUserId, array $changes): bool
    {
        $this->assertAdmin($actorUserId);
        $this->assertNotProtectedSuperAdmin($actorUserId, $targetUserId);

        $allowed = ['real_name', 'email', 'status'];
        $set = [];
        $params = ['id' => $targetUserId];

        foreach ($allowed as $column) {
            if (array_key_exists($column, $changes)) {
                $set[] = $column . ' = :' . $column;
                $params[$column] = $changes[$column];
            }
        }

        if ($set === []) {
            return false;
        }

        $sql = 'UPDATE users SET ' . implode(', ', $set) . ' WHERE id = :id AND deleted_at IS NULL';
        $stmt = $this->pdo->prepare($sql);
        $ok = $stmt->execute($params);

        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $context['changed_fields'] = array_keys($params);
            $this->auditLogger->log('admin.user.updated', $actorUserId, $targetUserId, $context);
            $this->logger->info('admin.user.updated', ['target_user_id' => $targetUserId, 'request_id' => $context['request_id']]);
        }

        return $ok;
    }

    public function assignRole(int $actorUserId, int $targetUserId, string $role): bool
    {
        $this->assertAdmin($actorUserId);

        if ($role === 'super_admin' && !$this->roles->hasRole($actorUserId, 'super_admin')) {
            return false;
        }

        $ok = $this->roles->assignRole($targetUserId, $role);
        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $context['role'] = $role;
            $this->auditLogger->log('admin.user.role_assigned', $actorUserId, $targetUserId, $context);
            $this->logger->info('admin.user.role_assigned', ['target_user_id' => $targetUserId, 'request_id' => $context['request_id']]);
        }

        return $ok;
    }

    public function revokeRole(int $actorUserId, int $targetUserId, string $role): bool
    {
        $this->assertAdmin($actorUserId);

        if ($role === 'super_admin' && !$this->roles->hasRole($actorUserId, 'super_admin')) {
            return false;
        }

        if ($role === 'super_admin' && $this->isLastSuperAdmin($targetUserId)) {
            return false;
        }

        $ok = $this->roles->revokeRole($targetUserId, $role);
        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $context['role'] = $role;
            $this->auditLogger->log('admin.user.role_revoked', $actorUserId, $targetUserId, $context);
            $this->logger->info('admin.user.role_revoked', ['target_user_id' => $targetUserId, 'request_id' => $context['request_id']]);
        }

        return $ok;
    }

    public function blockUser(int $actorUserId, int $targetUserId): bool
    {
        return $this->updateUser($actorUserId, $targetUserId, ['status' => 'blocked']);
    }

    public function softDeleteUser(int $actorUserId, int $targetUserId): bool
    {
        $this->assertAdmin($actorUserId);
        $this->assertNotProtectedSuperAdmin($actorUserId, $targetUserId);

        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET deleted_at = UTC_TIMESTAMP(), status = "disabled"
             WHERE id = :id AND deleted_at IS NULL'
        );
        $ok = $stmt->execute(['id' => $targetUserId]);

        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('admin.user.soft_deleted', $actorUserId, $targetUserId, $context);
            $this->logger->warning('admin.user.soft_deleted', ['target_user_id' => $targetUserId, 'request_id' => $context['request_id']]);
        }

        return $ok;
    }

    public function revokeUserSessions(int $actorUserId, int $targetUserId): bool
    {
        $this->assertAdmin($actorUserId);

        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = UTC_TIMESTAMP()
             WHERE user_id = :user_id AND revoked_at IS NULL'
        );
        $ok = $stmt->execute(['user_id' => $targetUserId]);

        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('admin.user.sessions_revoked', $actorUserId, $targetUserId, $context);
            $this->logger->warning('admin.user.sessions_revoked', ['target_user_id' => $targetUserId, 'request_id' => $context['request_id']]);
        }

        return $ok;
    }

    private function assertAdmin(int $actorUserId): void
    {
        if (!$this->roles->hasRole($actorUserId, 'admin') && !$this->roles->hasRole($actorUserId, 'super_admin')) {
            throw new \RuntimeException('Forbidden');
        }
    }

    private function assertNotProtectedSuperAdmin(int $actorUserId, int $targetUserId): void
    {
        $targetIsSuperAdmin = $this->roles->hasRole($targetUserId, 'super_admin');
        $actorIsSuperAdmin = $this->roles->hasRole($actorUserId, 'super_admin');

        if ($targetIsSuperAdmin && !$actorIsSuperAdmin) {
            throw new \RuntimeException('Forbidden');
        }
    }

    private function isLastSuperAdmin(int $targetUserId): bool
    {
        if (!$this->roles->hasRole($targetUserId, 'super_admin')) {
            return false;
        }

        $stmt = $this->pdo->query(
            'SELECT COUNT(*)
             FROM user_roles ur
             INNER JOIN roles r ON r.id = ur.role_id
             WHERE r.name = "super_admin"'
        );
        $count = (int) $stmt->fetchColumn();

        return $count <= 1;
    }
}
