<?php
declare(strict_types=1);

namespace DropProtocol\Amphp\Handler;

use Amp\Http\HttpStatus;
use Amp\Http\Server\Request;
use Amp\Http\Server\RequestHandler;
use Amp\Http\Server\Response;
use DropProtocol\DropProtocolService;
use DropProtocol\Exceptions\SessionLimitException;

/**
 * Request handler for authentication endpoints
 */
final class AuthHandler implements RequestHandler
{
    private DropProtocolService $dropService;
    
    public function __construct(DropProtocolService $dropService)
    {
        $this->dropService = $dropService;
    }

    public function handleRequest(Request $request): Response
    {
        $cookies = $this->parseCookies($request);
        $_COOKIE = $cookies;
        $_SERVER['HTTP_USER_AGENT'] = $request->getHeader('user-agent') ?? '';
        $_SERVER['REMOTE_ADDR'] = $request->getClient()->getRemoteAddress()->toString();
        
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        
        return match (true) {
            $method === 'POST' && $path === '/api/login' => $this->handleLogin($request),
            $method === 'POST' && $path === '/api/logout' => $this->handleLogout(),
            $method === 'POST' && $path === '/api/logout-all' => $this->handleLogoutAll(),
            $method === 'GET' && $path === '/api/sessions' => $this->handleGetSessions(),
            default => new Response(
                status: HttpStatus::NOT_FOUND,
                headers: ['content-type' => 'application/json'],
                body: json_encode(['error' => 'Not found'])
            )
        };
    }
    
    /**
     * Handle login request
     *
     * @param Request $request
     * @return Response
     */
    private function handleLogin(Request $request): Response
    {
        $body = $request->getBody()->buffer();
        $data = json_decode($body, true);
        
        $userId = $data['user_id'] ?? null;
        $userData = $data['user_data'] ?? [];
        
        if (!$userId) {
            return new Response(
                status: HttpStatus::BAD_REQUEST,
                headers: ['content-type' => 'application/json'],
                body: json_encode(['error' => 'user_id is required'])
            );
        }
        
        try {
            $session = $this->dropService->login($userId, $userData);
            
            $response = new Response(
                status: HttpStatus::OK,
                headers: ['content-type' => 'application/json'],
                body: json_encode([
                    'message' => 'Login successful',
                    'expires_in' => $session['expires']
                ])
            );
            
            $this->syncCookies($response);
            
            return $response;
            
        } catch (SessionLimitException $e) {
            return new Response(
                status: HttpStatus::TOO_MANY_REQUESTS,
                headers: ['content-type' => 'application/json'],
                body: json_encode([
                    'error' => 'Session limit exceeded',
                    'message' => $e->getMessage()
                ])
            );
        }
    }
    
    /**
     * Handle logout request
     *
     * @return Response
     */
    private function handleLogout(): Response
    {
        $this->dropService->logout();
        
        $response = new Response(
            status: HttpStatus::OK,
            headers: ['content-type' => 'application/json'],
            body: json_encode(['message' => 'Logged out successfully'])
        );
        
        $this->syncCookies($response);
        
        return $response;
    }
    
    /**
     * Handle logout all request
     *
     * @return Response
     */
    private function handleLogoutAll(): Response
    {
        $this->dropService->logoutAll();
        
        $response = new Response(
            status: HttpStatus::OK,
            headers: ['content-type' => 'application/json'],
            body: json_encode(['message' => 'Logged out from all devices'])
        );
        
        $this->syncCookies($response);
        
        return $response;
    }
    
    /**
     * Handle get sessions request
     *
     * @return Response
     */
    private function handleGetSessions(): Response
    {
        $count = $this->dropService->getActiveSessionCount();
        
        return new Response(
            status: HttpStatus::OK,
            headers: ['content-type' => 'application/json'],
            body: json_encode([
                'active_sessions' => $count
            ])
        );
    }
    
    /**
     * Parse cookies from request
     *
     * @param Request $request
     * @return array<string, string>
     */
    private function parseCookies(Request $request): array
    {
        $cookieHeader = $request->getHeader('cookie');
        if (!$cookieHeader) {
            return [];
        }
        
        $cookies = [];
        foreach (explode('; ', $cookieHeader) as $cookie) {
            $parts = explode('=', $cookie, 2);
            if (count($parts) === 2) {
                $cookies[$parts[0]] = urldecode($parts[1]);
            }
        }
        
        return $cookies;
    }
    
    /**
     * Sync PHP cookies to response
     *
     * @param Response $response
     * @return void
     */
    private function syncCookies(Response $response): void
    {
        foreach (headers_list() as $header) {
            if (stripos($header, 'Set-Cookie:') === 0) {
                $cookieValue = substr($header, 12);
                $response->setHeader('set-cookie', $cookieValue);
            }
        }
        
        header_remove('Set-Cookie');
    }
}
