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
use DropProtocol\Amphp\Services\AmphpCookieManager;

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
        
        $_SERVER['HTTP_USER_AGENT'] = $request->getHeader('user-agent') ?? '';
        $_SERVER['REMOTE_ADDR'] = $this->getClientIp($request);
        $_SERVER['REQUEST_METHOD'] = $request->getMethod();
        
        $previousCookies = $_COOKIE;
        $_COOKIE = $cookies;
        
        try {
            $session = $this->dropService->validate();
            $request->setAttribute(self::ATTRIBUTE_KEY, $session);
        } catch (InvalidSessionException | SecurityViolationException $e) {
            if ($this->required) {
                $_COOKIE = $previousCookies;
                
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
        } finally {
            // Always restore $_COOKIE to avoid polluting other requests
            $_COOKIE = $previousCookies;
        }

        $response = $next->handleRequest($request);
        
        $this->syncCookies($response);
        
        return $response;
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
     * Sync cookies to response headers
     *
     * @param Response $response
     * @return void
     */
    private function syncCookies(Response $response): void
    {
        $cookieManager = $this->dropService->getCookieManager();
        
        if ($cookieManager instanceof AmphpCookieManager) {
            $queuedCookies = $cookieManager->getQueuedCookies();
            
            foreach ($queuedCookies as $name => $data) {
                $expiryTimestamp = $data['options']['expires'] ?? (time() + 1800);
                
                // Use !empty() to handle empty strings and false values properly
                $secure = !empty($data['options']['secure']);
                $httpOnly = !empty($data['options']['httponly']);
                
                $cookie = new \Amp\Http\Cookie\ResponseCookie(
                    $name,
                    $data['value'],
                    \Amp\Http\Cookie\CookieAttributes::default()
                        ->withPath($data['options']['path'] ?: '/')
                        ->withDomain($data['options']['domain'] ?: '')
                        ->withSecure($secure)
                        ->withHttpOnly($httpOnly)
                        ->withSameSite($data['options']['samesite'] ?: 'Lax')
                        ->withExpiry(new \DateTimeImmutable('@' . $expiryTimestamp))
                );
                
                $response->setCookie($cookie);
            }
        } else {
            foreach (headers_list() as $header) {
                if (stripos($header, 'Set-Cookie:') === 0) {
                    $cookieValue = substr($header, 12);
                    $response->setHeader('set-cookie', trim($cookieValue));
                }
            }
            header_remove('Set-Cookie');
        }
    }
    /**
     * Get client IP address without port
     *
     * @param Request $request
     * @return string
     */
    private function getClientIp(Request $request): string
    {
        $address = $request->getClient()->getRemoteAddress()->toString();
        
        $lastColon = strrpos($address, ':');
        if ($lastColon !== false) {
            if (str_contains($address, ']')) {
                $ip = substr($address, 0, $lastColon);
                return trim($ip, '[]');
            }
            
            return substr($address, 0, $lastColon);
        }
        
        return $address;
    }
}
