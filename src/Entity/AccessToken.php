<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Entity;

use Lcobucci\JWT\Token;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use DateTimeImmutable;
use League\Bundle\OAuth2ServerBundle\Event\BeforeJwtTokenBuildEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;

class AccessToken implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
    use TokenEntityTrait;

    private static ?EventDispatcherInterface $eventDispatcher = null;

    public static function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        self::$eventDispatcher = $eventDispatcher;
    }

    private function convertToJWT(): Token
    {
        $this->initJwtConfiguration();
        $builder = $this->jwtConfiguration->builder();

        if (self::$eventDispatcher) {
            $event = new BeforeJwtTokenBuildEvent($builder, $this);
            self::$eventDispatcher->dispatch($event, OAuth2Events::BEFORE_JWT_TOKEN_BUILD);
            $builder = $event->getBuilder();
        }

        return $builder
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }
}
