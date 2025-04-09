<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Event;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Événement déclenché juste avant la construction finale du token JWT.
 * Permet d'ajouter des claims personnalisés au Builder.
 */
final class BeforeJwtTokenBuildEvent extends Event
{
    private Builder $builder;
    private AccessTokenEntityInterface $accessToken;

    public function __construct(Builder $builder, AccessTokenEntityInterface $accessToken)
    {
        $this->builder = $builder;
        $this->accessToken = $accessToken;
    }

    public function getBuilder(): Builder
    {
        return $this->builder;
    }

    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }
} 