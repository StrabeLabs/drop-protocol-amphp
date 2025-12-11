<?php
declare(strict_types=1);

namespace DropProtocol\Amphp\Services;

use DropProtocol\Contracts\CookieManagerInterface;

class AmphpCookieManager implements CookieManagerInterface
{
    private array $queuedCookies = [];
    private array $requestCookies = [];

    public function setCookie(string $name, string $value, array $options): void
    {
        $this->queuedCookies[$name] = [
            'value' => $value,
            'options' => $options
        ];
    }

    public function getQueuedCookies(): array
    {
        $cookies = $this->queuedCookies;
        $this->queuedCookies = []; // Clear after reading
        return $cookies;
    }

    /**
     * Set request cookies from incoming HTTP request
     * 
     * @param array $cookies Associative array of cookie name => value
     */
    public function setRequestCookies(array $cookies): void
    {
        $this->requestCookies = $cookies;
    }

    /**
     * Get a cookie value from the incoming request
     * 
     * @param string $name Cookie name
     * @return string|null Cookie value or null if not found
     */
    public function getRequestCookie(string $name): ?string
    {
        return $this->requestCookies[$name] ?? null;
    }

    /**
     * Get all request cookies
     * 
     * @return array Associative array of cookie name => value
     */
    public function getRequestCookies(): array
    {
        return $this->requestCookies;
    }
}
