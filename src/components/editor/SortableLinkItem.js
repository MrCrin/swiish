import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

function SortableLinkItem({ link, children }) {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id: link.id });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition
  };
  return children({ setNodeRef, style, attributes, listeners });
}

export default SortableLinkItem;
