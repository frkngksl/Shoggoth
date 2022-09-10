ENTRY(alignstack)
SECTIONS
{
	.text :
	{
    	*(.text.alignstack)
		*(.text.loadPE)
	}
}
