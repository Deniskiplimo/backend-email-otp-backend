export const runSafe = async (f) => {
    try {
        return { ok: true, value: await f() };
    }
    catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            return { ok: false, isAborted: true };
        }
        return { ok: false, error };
    }
};
