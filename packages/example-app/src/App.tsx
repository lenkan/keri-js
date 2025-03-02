import styles from "./App.module.css";
import { useSearchParams } from "react-router-dom";
import { ResolveOobiForm } from "./components/ResolveOobiForm.tsx";
import { EventList } from "./components/EventList.tsx";
import { useCallback, useEffect, useState } from "react";
import type { Message } from "keri/web";
import { parse } from "keri/web";

export function App() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [events, setEvents] = useState<Message[]>([]);
  const url = searchParams.get("url");

  const fetchEvents = useCallback(async () => {
    if (!url) {
      return;
    }

    const response = await fetch(url);
    if (!response.body) {
      return;
    }

    for await (const chunk of parse(response.body)) {
      setEvents((prev) => [...prev, chunk]);
    }
  }, [url]);

  useEffect(() => {
    if (!url) {
      setSearchParams({ url: "./samples/geda.cesr" });
    }
  }, []);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  async function handleResolveOobi(url: string) {
    setSearchParams({ url });
  }

  return (
    <div className={styles.container}>
      <ResolveOobiForm initialValue={url ?? undefined} onSubmit={handleResolveOobi} />
      <EventList frames={events} />;
    </div>
  );
}
