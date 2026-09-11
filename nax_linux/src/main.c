/* nax_linux/src/main.c — ELF executable entry point
 *
 * Thin wrapper that calls agent_run() from agent.c.
 * Compiled with: gcc ... -o nax_linux (produces ELF executable) */

extern int agent_run(void);

int main(void)
{
    return agent_run();
}
