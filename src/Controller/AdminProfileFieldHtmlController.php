<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\AdminProfileFieldServiceInterface;
use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Security\CsrfService;

final class AdminProfileFieldHtmlController
{
    public function __construct(
        private readonly AdminProfileFieldServiceInterface $service,
        private readonly TemplateRendererInterface $renderer,
        private readonly CsrfService $csrf,
    ) {
    }

    public function show(int $actorUserId, ?string $message = null): string
    {
        return $this->renderer->render('admin/profile_fields', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'definitions' => $this->service->listDefinitions($actorUserId),
        ]);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function upsert(int $actorUserId, array $input): string
    {
        $this->service->upsertDefinition($actorUserId, (string) ($input['field_key'] ?? ''), $input);

        return $this->show($actorUserId, 'Field definition saved.');
    }

    /**
     * @param array<string, mixed> $input
     */
    public function delete(int $actorUserId, array $input): string
    {
        $this->service->deleteDefinition($actorUserId, (string) ($input['field_key'] ?? ''));

        return $this->show($actorUserId, 'Field definition deleted.');
    }

    public function showUserProfile(int $actorUserId, int $targetUserId, string $query = '', int $limit = 50, int $offset = 0, ?string $message = null): string
    {
        $profile = $this->service->viewUserProfileFields($actorUserId, $targetUserId, $query, $limit, $offset);

        return $this->renderer->render('admin/user_profile_fields', [
            'message' => $message,
            'user' => $profile['user'],
            'profileFields' => $profile['profile_fields'],
            'total' => $profile['total'],
            'query' => $profile['query'],
            'limit' => $profile['limit'],
            'offset' => $profile['offset'],
        ]);
    }
}
