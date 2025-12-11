<?php

declare(strict_types=1);

namespace DropProtocol\Amphp\Storage;

use Amp\Redis\RedisClient;
use DropProtocol\Contracts\StorageInterface;

/**
 * Async Redis storage implementation for AMPHP
 * 
 * Uses amphp/redis for non-blocking Redis operations.
 */
final class AmphpRedisStorage implements StorageInterface
{
    private RedisClient $redis;
    private string $prefix;

    /**
     * @param RedisClient $redis AMPHP Redis client
     * @param string $prefix Key prefix for namespacing
     */
    public function __construct(RedisClient $redis, string $prefix = 'drop:')
    {
        $this->redis = $redis;
        $this->prefix = $prefix;
    }

    public function store(string $sessionId, string $userId, array $data, int $ttl): void
    {
        $key = $this->prefix . 'session:' . $sessionId;
        $sessionData = [
            'user_id' => $userId,
            'data' => $data,
            'created_at' => $data['created_at'] ?? time(),
            'last_activity' => time(),
        ];

        $this->redis->set($key, json_encode($sessionData));
        $this->redis->expireIn($key, $ttl);

        $userKey = $this->prefix . 'user:' . $userId;
        $userSet = $this->redis->getSet($userKey);
        $userSet->add($sessionId);
        $this->redis->expireIn($userKey, $ttl);
    }

    public function retrieve(string $sessionId): ?array
    {
        $key = $this->prefix . 'session:' . $sessionId;
        $data = $this->redis->get($key);

        if ($data === null) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    public function delete(string $sessionId): void
    {
        $key = $this->prefix . 'session:' . $sessionId;

        $sessionData = $this->retrieve($sessionId);
        
        $this->redis->delete($key);
        
        if ($sessionData && isset($sessionData['user_id'])) {
            $userKey = $this->prefix . 'user:' . $sessionData['user_id'];
            $userSet = $this->redis->getSet($userKey);
            $userSet->remove($sessionId);
        }
    }

    public function deleteUserSessions(string $userId): void
    {
        $userKey = $this->prefix . 'user:' . $userId;
        $userSet = $this->redis->getSet($userKey);
        $sessions = $userSet->getAll();

        if (!empty($sessions)) {
            foreach ($sessions as $sessionId) {
                $this->delete($sessionId);
            }
            $this->redis->delete($userKey);
        }
    }
    public function touch(string $sessionId, int $ttl): void
    {
        $key = $this->prefix . 'session:' . $sessionId;

        $data = $this->retrieve($sessionId);
        if ($data) {
            $data['last_activity'] = time();
            $this->redis->set($key, json_encode($data));
            $this->redis->expireIn($key, $ttl);
        }
    }

    public function rotateAtomic(
        string $oldId,
        string $newId,
        string $userId,
        array $data,
        int $ttl
    ): bool {
        $oldKey = $this->prefix . 'session:' . $oldId;
        $newKey = $this->prefix . 'session:' . $newId;

        $script = <<<LUA
            if redis.call('exists', KEYS[1]) == 1 then
                local oldData = redis.call('get', KEYS[1])
                local decoded = cjson.decode(oldData)
                
                if decoded.user_id ~= ARGV[3] then
                    return 0
                end
                
                local newData = cjson.decode(ARGV[1])
                newData.created_at = decoded.created_at
                
                redis.call('set', KEYS[2], cjson.encode(newData))
                redis.call('expire', KEYS[2], ARGV[2])
                redis.call('del', KEYS[1])
                return 1
            else
                return 0
            end
LUA;

        $sessionData = json_encode([
            'user_id' => $userId,
            'data' => $data,
            'created_at' => $data['created_at'] ?? time(),
            'last_activity' => time(),
        ]);

        $result = $this->redis->eval($script, [$oldKey, $newKey], [$sessionData, $ttl, $userId]);

        return $result === 1;
    }

    public function countUserSessions(string $userId): int
    {
        $userKey = $this->prefix . 'user:' . $userId;
        $userSet = $this->redis->getSet($userKey);
        return $userSet->getSize();
    }

    public function updateUserData(string $sessionId, array $userData): bool
    {
        $key = $this->prefix . 'session:' . $sessionId;

        $sessionData = $this->retrieve($sessionId);
        if (!$sessionData) {
            return false;
        }

        $sessionData['data']['user_data'] = $userData;
        $sessionData['last_activity'] = time();

        $script = <<<LUA
            if redis.call('exists', KEYS[1]) == 1 then
                local ttl = redis.call('ttl', KEYS[1])
                if ttl > 0 then
                    redis.call('set', KEYS[1], ARGV[1])
                    redis.call('expire', KEYS[1], ttl)
                    return 1
                end
            end
            return 0
        LUA;

        $result = $this->redis->eval($script, [$key], [json_encode($sessionData)]);

        return $result === 1;
    }
}
