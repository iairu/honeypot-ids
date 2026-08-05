<?php

declare (strict_types=1);
namespace WpifyWooDeps\Wpify\Model;

use WpifyWooDeps\Wpify\Model\Attributes\TermPostsRelation;
class Category extends Term
{
    /**
     * Posts assigned to this category.
     *
     * @var Post[]
     */
    #[TermPostsRelation(Post::class)]
    public array $posts = array();
}
