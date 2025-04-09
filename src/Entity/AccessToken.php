<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Entity;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain as PlainToken;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use League\Bundle\OAuth2ServerBundle\Event\BeforeJwtTokenBuildEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use DateTimeImmutable;
use RuntimeException;

class AccessToken implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
    use TokenEntityTrait;

    private CryptKeyInterface $privateKey;

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    private static ?EventDispatcherInterface $eventDispatcher = null;

    public static function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        self::$eventDispatcher = $eventDispatcher;
    }

    private function convertToJWT(): PlainToken
    {
        if (!isset($this->privateKey)) {
            throw new RuntimeException('Private key has not been set');
        }

        $signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
        $lcobucciKey = InMemory::plainText(
            $this->privateKey->getKeyContents(),
            $this->privateKey->getPassPhrase() ?? ''
        );

        if ($this->privateKey->getKeyContents() === '') {
            throw new RuntimeException('Private key is empty');
        }

        $configuration = Configuration::forAsymmetricSigner(
            $signer,
            InMemory::plainText(''),
            $lcobucciKey
        );

        $builder = $configuration->builder();

        $builder
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('scopes', $this->getScopes());

        if (self::$eventDispatcher) {
            $event = new BeforeJwtTokenBuildEvent($builder, $this);
            self::$eventDispatcher->dispatch($event, OAuth2Events::BEFORE_JWT_TOKEN_BUILD);
            $builder = $event->getBuilder();
        }

        return $builder->getToken($configuration->signer(), $configuration->signingKey());
    }

    private function getSubjectIdentifier(): string
    {
        return $this->getUserIdentifier() ?? $this->getClient()->getIdentifier();
    }
}
