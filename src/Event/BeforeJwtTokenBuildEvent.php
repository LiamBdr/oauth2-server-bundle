<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Event;

use Lcobucci\JWT\Token\Builder as BuilderInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Symfony\Contracts\EventDispatcher\Event;

final class BeforeJwtTokenBuildEvent extends Event
{
    public function __construct(
        private BuilderInterface $builder,
        private readonly AccessTokenEntityInterface $accessToken
    ) {
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