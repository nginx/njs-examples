function to_lower_case(r, data, flags) {
    r.sendBuffer(data.toLowerCase(), flags);
}

export default {to_lower_case};
