import styles from "./EventList.module.css";

export interface EventListProps {
  frames: string[];
}

export function EventList(props: EventListProps) {
  return (
    <ul className={styles.list}>
      {props.frames.map((frame, index) => {
        if (frame.startsWith("{")) {
          return (
            <li className={styles.item} key={index}>
              <pre>{JSON.stringify(JSON.parse(frame), null, 2)}</pre>
            </li>
          );
        }

        return (
          <li className={styles.item} key={index}>
            <pre>{frame}</pre>
          </li>
        );
      })}
    </ul>
  );
}
