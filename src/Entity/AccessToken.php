<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Entity;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key as SignerKey;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token\Plain as PlainToken;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use League\Bundle\OAuth2ServerBundle\Event\BeforeJwtTokenBuildEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use DateTimeImmutable;

class AccessToken implements AccessTokenEntityInterface
{
    use AccessTokenTrait {
        convertToJWT as public traitConvertToJWT;
    }
    use EntityTrait;
    use TokenEntityTrait;

    private static ?EventDispatcherInterface $eventDispatcher = null;

    public static function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        self::$eventDispatcher = $eventDispatcher;
    }

    private function buildJwt(SignerKey $privateKey, Signer $signer): PlainToken
    {
        $configuration = Configuration::forAsymmetricSigner(
            $signer,
            InMemory::plainText(''),
            $privateKey
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

    public function convertToJWT(CryptKey $privateKey): PlainToken
    {
        $signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
        $lcobucciKey = InMemory::plainText(
            $privateKey->getKeyContents(),
            $privateKey->getPassPhrase() ?? ''
        );

        return $this->buildJwt($lcobucciKey, $signer);
    }

    private function getSubjectIdentifier(): string
    {
        return $this->getUserIdentifier() ?? $this->getClient()->getIdentifier();
    }
}
