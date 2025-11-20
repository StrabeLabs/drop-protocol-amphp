<?php
declare(strict_types=1);

namespace DropProtocol\Amphp\Services;

use DropProtocol\Contracts\CookieManagerInterface;

class AmphpCookieManager implements CookieManagerInterface
{
    private array $queuedCookies = [];

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
}
