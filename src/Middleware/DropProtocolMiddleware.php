<?php
declare(strict_types=1);

namespace DropProtocol\Amphp\Middleware;

use Amp\Http\HttpStatus;
use Amp\Http\Server\Middleware;
use Amp\Http\Server\Request;
use Amp\Http\Server\RequestHandler;
use Amp\Http\Server\Response;
use DropProtocol\DropProtocolService;
use DropProtocol\Exceptions\InvalidSessionException;
use DropProtocol\Exceptions\SecurityViolationException;

/**
 * Authentication middleware for AMPHP HTTP Server
 * 
 * Validates DROP Protocol sessions and attaches user data to request attributes.
 */
final class DropProtocolMiddleware implements Middleware
{
    public const ATTRIBUTE_KEY = 'drop_session';
    
    private DropProtocolService $dropService;
    private bool $required;
    
    /**
     * @param DropProtocolService $dropService DROP Protocol service instance
     * @param bool $required If true, rejects requests without valid session
     */
    public function __construct(DropProtocolService $dropService, bool $required = true)
    {
        $this->dropService = $dropService;
        $this->required = $required;
    }

    public function handleRequest(Request $request, RequestHandler $next): Response
    {
        $cookies = $this->parseCookies($request);
        
        $_COOKIE = $cookies;
        $_SERVER['HTTP_USER_AGENT'] = $request->getHeader('user-agent') ?? '';
        $_SERVER['REMOTE_ADDR'] = $request->getClient()->getRemoteAddress()->toString();
        $_SERVER['REQUEST_METHOD'] = $request->getMethod();
        
        try {
            $session = $this->dropService->validate();
            
            $request->setAttribute(self::ATTRIBUTE_KEY, $session);
            
            $response = $next->handleRequest($request);
            
            $this->syncCookies($response);
            
            return $response;
            
        } catch (InvalidSessionException | SecurityViolationException $e) {
            if ($this->required) {
                return new Response(
                    status: HttpStatus::UNAUTHORIZED,
                    headers: ['content-type' => 'application/json'],
                    body: json_encode([
                        'error' => 'Unauthorized',
                        'message' => $e->getMessage()
                    ])
                );
            }
            
            $request->setAttribute(self::ATTRIBUTE_KEY, null);
            return $next->handleRequest($request);
        }
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
     * Sync PHP cookies to response headers
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
