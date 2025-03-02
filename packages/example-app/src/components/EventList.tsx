import type { Message } from "keri/web";
import styles from "./EventList.module.css";

export interface EventListProps {
  frames: Message[];
}

export function EventList(props: EventListProps) {
  return (
    <ul className={styles.list}>
      {props.frames.map((frame, index) => {
        return (
          <li className={styles.item} key={index}>
            <pre>{JSON.stringify(frame.payload, null, 2)}</pre>
            {Object.entries(frame.attachments).map(([group, attachments]) => {
              return (
                <ul key={group}>
                  <li>{group}</li>
                  {attachments.map((attachment, index) => {
                    return (
                      <li key={index}>
                        <pre>{attachment}</pre>
                      </li>
                    );
                  })}
                </ul>
              );
            })}
          </li>
        );
      })}
    </ul>
  );
}
