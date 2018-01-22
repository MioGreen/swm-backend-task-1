<?php

namespace SailWithMe\Collections;

use Illuminate\Database\Eloquent\Collection;

class BaseFieldValuesCollection extends Collection
{
    protected $selectedValues = [];

    public function setSelectedValue($value)
    {
        $this->selectedValues[] = $value;
    }

    public function getSelectedValues()
    {
        if(count($this->selectedValues) == 0) {
            return null;
        }

        return (count($this->selectedValues) > 1) ? $this->selectedValues : reset($this->selectedValues);
    }
}