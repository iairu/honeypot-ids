<?php

declare (strict_types=1);
namespace WpifyWooDeps\Wpify\Model;

use WpifyWooDeps\Wpify\Model\Attributes\ChildTermsRelation;
use WpifyWooDeps\Wpify\Model\Attributes\ManyToOneRelation;
use WpifyWooDeps\Wpify\Model\Attributes\ReadOnlyProperty;
use WpifyWooDeps\Wpify\Model\Attributes\SourceObject;
use WpifyWooDeps\Wpify\Model\Attributes\TopLevelTermParentRelation;
use WpifyWooDeps\Wpify\Model\Interfaces\TermModelInterface;
class Term extends Model implements TermModelInterface
{
    /**
     * Term ID.
     */
    #[SourceObject('term_id')]
    public int $id = 0;
    /**
     * The term's name.
     */
    #[SourceObject('name')]
    public string $name = '';
    /**
     * The term's slug.
     */
    #[SourceObject('slug')]
    public string $slug = '';
    /**
     * The term's term_group.
     */
    #[SourceObject('term_group')]
    public int $group = 0;
    /**
     * Term Taxonomy ID.
     */
    #[SourceObject('term_taxonomy_id')]
    public int $taxonomy_id = 0;
    /**
     * The term's taxonomy name.
     */
    #[SourceObject('taxonomy')]
    public string $taxonomy = '';
    /**
     * The term's description.
     */
    #[SourceObject('description')]
    public string $description = '';
    /**
     * ID of a term's parent term.
     */
    #[SourceObject('parent')]
    public int $parent_id = 0;
    /**
     * Term's parent term.
     */
    #[ManyToOneRelation('parent_id')]
    public ?Term $parent = null;
    /**
     * Term's top level parent term.
     */
    #[TopLevelTermParentRelation]
    public ?Term $top_parent = null;
    /**
     * Children terms.
     *
     * @var Term[]
     */
    #[ChildTermsRelation]
    public array $children = array();
    /**
     * Cached object count for this term.
     */
    #[SourceObject('count')]
    public int $count = 0;
    /**
     * Stores the term object's sanitization level.
     *
     * Does not correspond to a database field.
     */
    #[SourceObject('filter')]
    public string $filter = 'raw';
    /**
     * The term's permalink.
     */
    #[ReadOnlyProperty]
    public string $permalink = '';
    /**
     * Used for wp_insert_term() or wp_update_term().
     */
    public string $alias_of = '';
    /**
     * Getter for permalink property.
     */
    public function get_permalink(): string
    {
        return get_term_link($this->id, $this->taxonomy);
    }
}
