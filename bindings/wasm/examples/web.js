import("../pkg/index.js").then((streams) => {

    console.log(streams)

    const greet = streams.Greet()
    
    console.log("greet: ", greet)
    
    let seed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    
    let author = streams.auth_new(seed);
    console.log("author: ", author);
});
