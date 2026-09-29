<?php

namespace App\Http\Resources\V1;

use App\Models\VersionRange;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin VersionRange
 */
class VersionRangeResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'type' => $this->type,
            'ecosystem' => $this->ecosystem,
            'package_manager' => $this->package_manager,
            'vendor' => $this->vendor,
            'product' => $this->product,
            'version_incl_start' => $this->version_incl_start,
            'version_excl_start' => $this->version_excl_start,
            'version_incl_end' => $this->version_incl_end,
            'version_excl_end' => $this->version_excl_end,
            'plugs_into' => $this->plugs_into,
        ];
    }
}
