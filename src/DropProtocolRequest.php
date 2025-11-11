<?php
declare(strict_types=1);

namespace DropProtocol\Amphp;

use Amp\Http\Server\Request;
use DropProtocol\Amphp\Middleware\DropProtocolMiddleware;

/**
 * Helper class to extract DROP Protocol session from request
 */
final class DropProtocolRequest
{
    /**
     * Get session data from request
     *
     * @param Request $request
     * @return array|null Session data or null if not authenticated
     */
    public static function getSession(Request $request): ?array
    {
        return $request->getAttribute(DropProtocolMiddleware::ATTRIBUTE_KEY);
    }
    
    /**
     * Get user ID from request
     *
     * @param Request $request
     * @return string|null User ID or null if not authenticated
     */
    public static function getUserId(Request $request): ?string
    {
        $session = self::getSession($request);
        return $session['user_id'] ?? null;
    }
    
    /**
     * Get user data from request
     *
     * @param Request $request
     * @return array User metadata
     */
    public static function getUserData(Request $request): array
    {
        $session = self::getSession($request);
        return $session['data']['user_data'] ?? [];
    }
    
    /**
     * Check if request is authenticated
     *
     * @param Request $request
     * @return bool
     */
    public static function isAuthenticated(Request $request): bool
    {
        return self::getSession($request) !== null;
    }
}
