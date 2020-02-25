<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace Hyperf\ConfigAliyunAcm;

use Closure;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\StdoutLoggerInterface;
use Hyperf\Guzzle\ClientFactory as GuzzleClientFactory;
use Hyperf\Utils\Codec\Json;
use Psr\Container\ContainerInterface;
use RuntimeException;

class Client implements ClientInterface
{
    public const PATH_CONFIG = '/diamond-server/config.co';
    public const PATH_BASE_STONE = '/diamond-server/basestone.do';

    /**
     * @var Closure
     */
    private $client;

    /**
     * @var ConfigInterface
     */
    private $config;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var array
     */
    private $servers;

    /**
     * @var array[]
     */
    private $cachedSecurityCredentials = [];

    /**
     * @var array
     */
    private $loadedConfigContentMd5 = [];

    public function __construct(ContainerInterface $container)
    {
        /**
         * @var GuzzleClientFactory $clientFactory
         */
        $clientFactory = $container->get(GuzzleClientFactory::class);
        $this->client = $clientFactory->create();
        $this->config = $container->get(ConfigInterface::class);
        $this->logger = $container->get(StdoutLoggerInterface::class);
    }

    public function getAllConfig()
    {
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $pageSize = 100;
        $result = [];
        for ($pageNo = 1; ; $pageNo++) {
            $response = Json::decode($this->request('GET', self::PATH_BASE_STONE, [
                'query' => [
                    'method' => 'getAllConfigByTenant',
                    'tenant' => $namespace,
                    'pageNo' => $pageNo,
                    'pageSize' => $pageSize,
                ]
            ]));
            if (empty($response) || empty($response['pageItems'])) break;
            $result = array_merge($result, $response['pageItems']);
            if ($response['pagesAvailable'] <= $response['pageNumber']) break;
        }
        return $result;
    }

    public function update(string $dataId, string $content): bool
    {
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $group = $this->config->get('aliyun_acm.group', 'DEFAULT_GROUP');
        $response = $this->request('POST', self::PATH_BASE_STONE, [
            'query' => [
                'method' => 'syncUpdateAll',
            ],
            'form_params' => [
                'tenant' => $namespace,
                'group' => $group,
                'dataId' => $dataId,
                'content' => $content,
            ]
        ]);
        return trim($response) === 'OK';
    }

    public function pull(): array
    {
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $group = $this->config->get('aliyun_acm.group', 'DEFAULT_GROUP');
        $dataId = $this->config->get('aliyun_acm.data_id', '');
        $dataIds = is_array($dataId) ? $dataId : [$dataId];
        return $this->pullDatas($namespace, $group, $dataIds);
    }

    /**
     * Pull the config values from configuration center with long pull, and then update the Config values.
     */
    public function longPull(): array
    {
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $group = $this->config->get('aliyun_acm.group', 'DEFAULT_GROUP');
        $dataId = $this->config->get('aliyun_acm.data_id', '');
        $dataIds = is_array($dataId) ? $dataId : [$dataId];
        $result = [];
        foreach ($this->listen($dataIds) as $dataId) {
            $this->logger->info("config {$dataId} in group {$group} changed");
            $newConfig = $this->pullData($namespace, $group, $dataId);
            $result = array_merge_recursive($result, $newConfig);
        }
        return $result;
    }

    /**
     * listen for the change event of some config items
     * @return string[] the changed config data ids as an array
     */
    public function listen(array $dataIds): array
    {
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $group = $this->config->get('aliyun_acm.group', 'DEFAULT_GROUP');
        $probeModifyRequest = '';
        foreach (array_values(array_unique($dataIds)) as $dataId) {
            $cache_key = "{$namespace}\x02{$group}\x02{$dataId}";
            $md5 = $this->loadedConfigContentMd5[$cache_key] ?? '';
            $probeModifyRequest .= "{$dataId}\x02{$group}\x02{$md5}\x02{$namespace}\x01";
        }
        $options = [
            'headers' => [
                'longPullingTimeout' => 60000
            ],
            'form_params' => [
                'Probe-Modify-Request' => $probeModifyRequest
            ]
        ];
        $changedDataIds = [];
        $response = urldecode($this->request('POST', self::PATH_CONFIG, $options));
        foreach (explode("\x01", $response) as $response_item) {
            $segs = explode("\x02", $response_item);
            if (count($segs) < 3) continue;
            $changedDataIds[] = $segs[0];
        }
        return $changedDataIds;
    }

    private function pullDatas(string $namespace, string $group, array $dataIds): array
    {
        $result = [];
        foreach (array_values(array_unique($dataIds)) as $dataId) {
            $result = array_merge_recursive($result, $this->pullData($namespace, $group, $dataId));
        }
        return $result;
    }

    public function pullData(string $namespace, string $group, string $dataId): array
    {
        $options = [
            'query' => [
                'tenant' => $namespace,
                'group' => $group,
                'dataId' => $dataId,
            ]
        ];
        $response_content = $this->request('GET', self::PATH_CONFIG, $options);
        if (! empty($response_content)) {
            $cache_key = "{$namespace}\x02{$group}\x02{$dataId}";
            $this->loadedConfigContentMd5[$cache_key] = md5($response_content);
            return Json::decode($response_content);
        }
        return [];
    }

    public function request(string $method, string $path, array $options): ?string
    {
        $client = $this->client;
        if (!$client instanceof \GuzzleHttp\Client) {
            throw new RuntimeException('aliyun acm: Invalid http client.');
        }

        // ACM config
        $endpoint = $this->config->get('aliyun_acm.endpoint', 'acm.aliyun.com');
        $namespace = $this->config->get('aliyun_acm.namespace', '');
        $group = $this->config->get('aliyun_acm.group', 'DEFAULT_GROUP');
        $accessKey = $this->config->get('aliyun_acm.access_key', '');
        $secretKey = $this->config->get('aliyun_acm.secret_key', '');
        $ecsRamRole = $this->config->get('aliyun_acm.ecs_ram_role', '');
        $securityToken = null;
        if (empty($accessKey) && ! empty($ecsRamRole)) {
            $securityCredentials = $this->getSecurityCredentialsWithEcsRamRole($ecsRamRole);
            if (! empty($securityCredentials)) {
                $accessKey = $securityCredentials['AccessKeyId'];
                $secretKey = $securityCredentials['AccessKeySecret'];
                $securityToken = $securityCredentials['SecurityToken'];
            }
        }


        try {
            if (!$this->servers) {
                // server list
                $response = $client->get("http://{$endpoint}:8080/diamond-server/diamond");
                if ($response->getStatusCode() !== 200) {
                    throw new RuntimeException('Get server list failed from Aliyun ACM.');
                }
                $this->servers = array_filter(explode("\n", $response->getBody()->getContents()));
            }
            $server = $this->servers[array_rand($this->servers)];

            // Submit the request
            if ($path === self::PATH_BASE_STONE && $method === 'GET') {
                // sign check of this special request doesn't need $group param
                // https://help.aliyun.com/document_detail/69590.html
                $requestHeaders = $this->buildRequestHeaders($accessKey, $secretKey, $securityToken, $namespace, null);
            } else {
                $requestHeaders = $this->buildRequestHeaders($accessKey, $secretKey, $securityToken, $namespace, $group);
            }
            $requestHeaders =
            $response = $client->request($method, "http://{$server}:8080{$path}", array_merge_recursive([
                'headers' => $requestHeaders,
            ], $options));
            if ($response->getStatusCode() !== 200) {
                throw new RuntimeException('Get config failed from Aliyun ACM.');
            }
            return $response->getBody()->getContents();
        } catch (\Throwable $throwable) {
            $this->logger->error(sprintf('%s[line:%d] in %s', $throwable->getMessage(), $throwable->getLine(), $throwable->getFile()));
        }
        return null;
    }

    private function buildRequestHeaders(
        string $accessKey,
        string $secretKey,
        ?string $securityToken,
        string $namespace,
        ?string $group
    ): array
    {
        $timestamp = round(microtime(true) * 1000);
        $sign_content = is_null($group) ? "{$namespace}+{$timestamp}" : "{$namespace}+{$group}+{$timestamp}";
        $sign = base64_encode(hash_hmac('sha1', $sign_content, $secretKey, true));
        return [
            'Spas-AccessKey' => $accessKey,
            'timeStamp' => $timestamp,
            'Spas-Signature' => $sign,
            'Spas-SecurityToken' => $securityToken ?? '',
            'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
        ];
    }

    /**
     * Get ECS RAM authorization.
     * @see https://help.aliyun.com/document_detail/72013.html
     * @see https://help.aliyun.com/document_detail/54579.html?#title-9w8-ufj-kz6
     */
    private function getSecurityCredentialsWithEcsRamRole(string $ecsRamRole): ?array
    {
        $securityCredentials = $this->cachedSecurityCredentials[$ecsRamRole] ?? null;
        if (! empty($securityCredentials) && time() > strtotime($securityCredentials['Expiration']) - 60) {
            $securityCredentials = null;
        }
        if (empty($securityCredentials)) {
            $response = $this->client->get('http://100.100.100.200/latest/meta-data/ram/security-credentials/' . $ecsRamRole);
            if ($response->getStatusCode() !== 200) {
                throw new RuntimeException('Get config failed from Aliyun ACM.');
            }
            $securityCredentials = Json::decode($response->getBody()->getContents());
            if (! empty($securityCredentials)) {
                $this->cachedSecurityCredentials[$ecsRamRole] = $securityCredentials;
            }
        }
        return $securityCredentials;
    }
}
