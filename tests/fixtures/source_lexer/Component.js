import { createReactAgent } from "@langchain/langgraph/prebuilt";
export const Panel = () => (
    <section>
        <p>match src/*.js files</p>
        <p>createReactAgent(fake) is documentation</p>
        <span>Agent configuration</span>
        <div>
            {createReactAgent({})}
        </div>
    </section>
);
