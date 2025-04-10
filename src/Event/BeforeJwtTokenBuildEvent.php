<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Event;

use Lcobucci\JWT\Token\Builder as BuilderInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Événement déclenché juste avant la construction finale du token JWT.
 * Permet d'ajouter des claims personnalisés au Builder.
 */
final class BeforeJwtTokenBuildEvent extends Event
{
    private BuilderInterface $builder;
    private AccessTokenEntityInterface $accessToken;

    public function __construct(BuilderInterface $builder, AccessTokenEntityInterface $accessToken)
    {
        $this->builder = $builder;
        $this->accessToken = $accessToken;
    }

    public function getBuilder(): BuilderInterface
    {
        return $this->builder;
    }

    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }

    public function setBuilder(BuilderInterface $builder): void
    {
        $this->builder = $builder;
    }
} 