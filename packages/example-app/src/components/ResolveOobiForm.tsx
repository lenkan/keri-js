export interface ResolveOobiFormProps {
  initialValue?: string;
  onSubmit(url: string): void;
}

function resolveInputs(form: HTMLFormElement): Record<string, string> {
  const inputs = form.querySelectorAll("input");
  const result: Record<string, string> = {};

  inputs.forEach((input) => {
    result[input.name] = input.value;
  });

  return result;
}

export function ResolveOobiForm(props: ResolveOobiFormProps) {
  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = resolveInputs(event.currentTarget);
    props.onSubmit(data.url);
  }

  return (
    <form onSubmit={handleSubmit}>
      <label>
        Enter OOBI URL:
        <input type="text" name="url" required aria-required defaultValue={props.initialValue} />
      </label>
      <button type="submit">Resolve</button>
    </form>
  );
}
