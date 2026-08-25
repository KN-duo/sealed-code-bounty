import { Link } from "../router";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/states";

export function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      message="That route doesn't exist. Head back to the bounty board."
      action={
        <Link to="/">
          <Button variant="primary">Go to board</Button>
        </Link>
      }
    />
  );
}
