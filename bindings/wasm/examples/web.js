import("../pkg/index.js").then((streams) => {

    console.log(streams)

    const greet = streams.Greet()
    
    console.log("greet: ", greet)
});
